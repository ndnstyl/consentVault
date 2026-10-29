-- Billing (Stripe hosted pages only). Nothing about payment is stored but Stripe ids and plan facts: no card, bank or
-- address data. Adds the trial and past_due organisation statuses, the append-only status history, the Stripe account
-- link, the once-only webhook event store and the per-day usage count.
--
-- Access: billing_account, usage_day and org_status_history are tenant tables (row-level security on current_org(),
-- the runtime role may read them and never writes them directly). billing_event is a platform table: the webhook
-- arrives before any tenant is known, so it is owner-only and reached through functions.
-- Every function that takes an organisation as an argument (the webhook path) enters that organisation with a
-- 60 second token it signs itself, so the owner stays bound by row-level security; the functions that act on "the
-- current organisation" (the usage job) filter on current_org() themselves and need the worker:usage scope.

-- Statuses ---------------------------------------------------------------------------------------------------------
ALTER TABLE consentvault.organization DROP CONSTRAINT organization_status_check;
ALTER TABLE consentvault.organization ADD CONSTRAINT organization_status_check
    CHECK (status IN ('trial', 'active', 'past_due', 'suspended', 'offboarding', 'closed'));

-- Status history: the status in force at any moment; append-only -----------------------------------------------------
CREATE TABLE consentvault.org_status_history (
    org_id  uuid NOT NULL REFERENCES consentvault.organization (org_id),
    seq     integer NOT NULL CHECK (seq >= 1),
    status  text NOT NULL CHECK (status IN ('trial', 'active', 'past_due', 'suspended', 'offboarding', 'closed')),
    from_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    cause   text NOT NULL CHECK (cause IN ('created', 'invoice_paid', 'payment_failed', 'subscription_deleted',
                                           'operator', 'offboard_run')),
    actor   text NOT NULL CHECK (length(actor) BETWEEN 1 AND 200),
    PRIMARY KEY (org_id, seq)
);
CREATE TRIGGER org_status_history_append_only BEFORE UPDATE OR DELETE ON consentvault.org_status_history
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER org_status_history_no_truncate BEFORE TRUNCATE ON consentvault.org_status_history
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- The Stripe link of one organisation: Stripe ids and plan facts copied from the Price at link time -----------------
CREATE TABLE consentvault.billing_account (
    org_id                 uuid PRIMARY KEY REFERENCES consentvault.organization (org_id),
    stripe_customer_id     text NOT NULL UNIQUE CHECK (stripe_customer_id ~ '^cus_[A-Za-z0-9_]{1,100}$'),
    stripe_subscription_id text CHECK (stripe_subscription_id ~ '^sub_[A-Za-z0-9_]{1,100}$'),
    price_id               text CHECK (price_id ~ '^price_[A-Za-z0-9_]{1,100}$'),
    status                 text CHECK (status IN ('incomplete', 'incomplete_expired', 'trialing', 'active',
                                                  'past_due', 'canceled', 'unpaid', 'paused')),
    plan_id                text CHECK (length(plan_id) BETWEEN 1 AND 60),
    plan_name              text CHECK (length(plan_name) BETWEEN 1 AND 120),
    included_events        bigint CHECK (included_events >= 0),
    included_gate_checks   bigint CHECK (included_gate_checks >= 0),
    period_start           timestamptz,
    period_end             timestamptz,
    updated_at             timestamptz NOT NULL DEFAULT now()
);

-- Every Stripe event, once. Owner-only: no grant to any runtime role. -------------------------------------------------
CREATE TABLE consentvault.billing_event (
    stripe_event_id text PRIMARY KEY CHECK (stripe_event_id ~ '^evt_[A-Za-z0-9_]{1,100}$'),
    type            text NOT NULL CHECK (length(type) BETWEEN 1 AND 200),
    received_at     timestamptz NOT NULL DEFAULT now(),
    outcome         text CHECK (length(outcome) BETWEEN 1 AND 60),
    org_id          uuid
);
CREATE INDEX billing_event_outcome_idx ON consentvault.billing_event (outcome);
REVOKE ALL ON consentvault.billing_event FROM PUBLIC;

-- The day's count per organisation. gate_checks is NULL while the count could not be read; never 0 for unread.
CREATE TABLE consentvault.usage_day (
    org_id      uuid NOT NULL REFERENCES consentvault.organization (org_id),
    day         date NOT NULL,
    events      bigint NOT NULL CHECK (events >= 0),
    gate_checks bigint CHECK (gate_checks >= 0),
    reported_at timestamptz,
    stripe_ack  jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (org_id, day)
);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['billing_account', 'usage_day', 'org_status_history'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
    END LOOP;
END
$$;
GRANT SELECT ON consentvault.billing_account, consentvault.usage_day, consentvault.org_status_history
    TO consentvault_app;

-- Status history writer: every status change, from any lane, writes one row -------------------------------------------
-- Owned by the operator role (BYPASSRLS): an owner-side change made with no tenant entered (a DBA's repair, a test) still
-- leaves its row. The cause and actor come from the transaction-local settings consentvault.status_cause and
-- consentvault.status_actor; with none set a change is 'operator' by 'unknown', so nothing is ever unrecorded.
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
GRANT SELECT (org_id, seq), INSERT ON consentvault.org_status_history TO consentvault_operator;
GRANT SELECT (org_id, status, created_at) ON consentvault.organization TO consentvault_operator;
GRANT SELECT (org_id, stripe_customer_id) ON consentvault.billing_account TO consentvault_operator;

CREATE FUNCTION consentvault.org_status_history_log() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c text;
    a text;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' THEN
        c := 'created';
    ELSE
        c := coalesce(nullif(pg_catalog.current_setting('consentvault.status_cause', true), ''), 'operator');
    END IF;
    a := coalesce(nullif(pg_catalog.current_setting('consentvault.status_actor', true), ''),
                  CASE TG_OP WHEN 'INSERT' THEN 'system' ELSE 'unknown' END);
    INSERT INTO consentvault.org_status_history (org_id, seq, status, cause, actor)
        SELECT NEW.org_id, coalesce(max(h.seq), 0) + 1, NEW.status, c, a
          FROM consentvault.org_status_history h WHERE h.org_id = NEW.org_id;
    RETURN NULL;
END;
$$;
ALTER FUNCTION consentvault.org_status_history_log() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.org_status_history_log() FROM PUBLIC;
CREATE TRIGGER organization_status_history AFTER INSERT OR UPDATE OF status ON consentvault.organization
    FOR EACH ROW EXECUTE FUNCTION consentvault.org_status_history_log();

-- Organisations that exist before this migration start their history at their creation, in the status they hold.
SET LOCAL ROLE consentvault_operator;
INSERT INTO consentvault.org_status_history (org_id, seq, status, from_at, cause, actor)
    SELECT o.org_id, 1, o.status, o.created_at, 'created', 'migration' FROM consentvault.organization o;
RESET ROLE;

-- Pre-tenant lookup of the organisation a Stripe customer belongs to (operator-owned, like resolve_credential).
-- The hint is the org_id Stripe carries in metadata, read from an object the vault fetched from Stripe by id.
CREATE FUNCTION consentvault.billing_resolve_org(p_customer text, p_org_hint uuid) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(
        (SELECT a.org_id FROM consentvault.billing_account a WHERE a.stripe_customer_id = p_customer),
        (SELECT o.org_id FROM consentvault.organization o WHERE o.org_id = p_org_hint));
$$;
ALTER FUNCTION consentvault.billing_resolve_org(text, uuid) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.billing_resolve_org(text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_resolve_org(text, uuid) TO consentvault_app;

-- Webhook event store ----------------------------------------------------------------------------------------------
-- true: first sight, recorded. false: this Stripe event id was seen before (a replay).
CREATE FUNCTION consentvault.billing_record_event(p_event_id text, p_type text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    added integer;
BEGIN
    INSERT INTO consentvault.billing_event (stripe_event_id, type) VALUES (p_event_id, p_type)
        ON CONFLICT (stripe_event_id) DO NOTHING;
    GET DIAGNOSTICS added = ROW_COUNT;
    RETURN added = 1;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.billing_record_event(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_record_event(text, text) TO consentvault_app;

CREATE FUNCTION consentvault.billing_finish_event(p_event_id text, p_org uuid, p_outcome text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE consentvault.billing_event SET outcome = p_outcome, org_id = p_org
     WHERE stripe_event_id = p_event_id AND outcome IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault billing: event % is not open (unknown, or its outcome is already set)', p_event_id
            USING ERRCODE = 'no_data_found';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.billing_finish_event(text, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_finish_event(text, uuid, text) TO consentvault_app;

-- How many events of each outcome the vault holds: the count behind "stored, ignored, counted".
CREATE FUNCTION consentvault.billing_event_outcomes() RETURNS TABLE (outcome text, n bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(e.outcome, 'open'), count(*) FROM consentvault.billing_event e GROUP BY 1 ORDER BY 1;
$$;
REVOKE ALL ON FUNCTION consentvault.billing_event_outcomes() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_event_outcomes() TO consentvault_app, consentvault_worker;

-- Link or update an organisation's Stripe account. NULL means "keep what is there". One customer per organisation.
CREATE FUNCTION consentvault.billing_link_account(
    p_org uuid, p_customer text, p_subscription text, p_price text, p_status text, p_plan_id text, p_plan_name text,
    p_included_events bigint, p_included_gate_checks bigint, p_period_start timestamptz, p_period_end timestamptz)
    RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    prev text := pg_catalog.current_setting('consentvault.org_token', true);
    held text;
BEGIN
    IF p_org IS NULL OR p_customer IS NULL THEN
        RAISE EXCEPTION 'consentvault billing: an organisation and a Stripe customer are required'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_catalog.set_config('consentvault.org_token',
                                  consentvault.sign_org_token(p_org, ARRAY['billing'], NULL, 60), true);
    SELECT stripe_customer_id INTO held FROM consentvault.billing_account WHERE org_id = p_org FOR UPDATE;
    IF FOUND AND held <> p_customer THEN
        RAISE EXCEPTION 'consentvault billing: organisation % is already linked to another Stripe customer', p_org
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NOT FOUND THEN
        INSERT INTO consentvault.billing_account (org_id, stripe_customer_id, stripe_subscription_id, price_id, status,
                plan_id, plan_name, included_events, included_gate_checks, period_start, period_end)
            VALUES (p_org, p_customer, p_subscription, p_price, p_status, p_plan_id, p_plan_name, p_included_events,
                    p_included_gate_checks, p_period_start, p_period_end);
    ELSE
        UPDATE consentvault.billing_account SET
            stripe_subscription_id = coalesce(p_subscription, stripe_subscription_id),
            price_id = coalesce(p_price, price_id),
            status = coalesce(p_status, status),
            plan_id = coalesce(p_plan_id, plan_id),
            plan_name = coalesce(p_plan_name, plan_name),
            included_events = coalesce(p_included_events, included_events),
            included_gate_checks = coalesce(p_included_gate_checks, included_gate_checks),
            period_start = coalesce(p_period_start, period_start),
            period_end = coalesce(p_period_end, period_end),
            updated_at = now()
          WHERE org_id = p_org;
    END IF;
    PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.billing_link_account(uuid, text, text, text, text, text, text, bigint, bigint,
    timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_link_account(uuid, text, text, text, text, text, text, bigint, bigint,
    timestamptz, timestamptz) TO consentvault_app;

-- The one place a webhook changes an organisation's status. Returns what happened:
--   changed | unchanged | refused_terminal (offboarding or closed: a webhook never moves them) | refused_transition.
-- Cause fixes the target: invoice_paid -> active, payment_failed -> past_due, subscription_deleted -> suspended.
-- p_only_from, when given, limits the change to organisations currently in one of those statuses (else 'unchanged').
CREATE FUNCTION consentvault.billing_apply_status(
    p_org uuid, p_to text, p_cause text, p_event_id text, p_only_from text[] DEFAULT NULL) RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    prev   text := pg_catalog.current_setting('consentvault.org_token', true);
    cur    text;
    legal  boolean;
BEGIN
    IF NOT ((p_cause = 'invoice_paid' AND p_to = 'active') OR (p_cause = 'payment_failed' AND p_to = 'past_due')
            OR (p_cause = 'subscription_deleted' AND p_to = 'suspended')) THEN
        RAISE EXCEPTION 'consentvault billing: cause % cannot lead to status %', p_cause, p_to
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_event_id IS NULL OR p_event_id !~ '^evt_[A-Za-z0-9_]{1,100}$' THEN
        RAISE EXCEPTION 'consentvault billing: a webhook status change must name its Stripe event'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_catalog.set_config('consentvault.org_token',
                                  consentvault.sign_org_token(p_org, ARRAY['billing'], NULL, 60), true);
    SELECT status INTO cur FROM consentvault.organization WHERE org_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault billing: organisation % does not exist', p_org USING ERRCODE = 'no_data_found';
    END IF;
    IF cur IN ('offboarding', 'closed') THEN
        PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
        RETURN 'refused_terminal';
    END IF;
    IF cur = p_to OR (p_only_from IS NOT NULL AND cur <> ALL (p_only_from)) THEN
        PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
        RETURN 'unchanged';
    END IF;
    legal := (p_to = 'active' AND cur IN ('trial', 'past_due', 'suspended'))
          OR (p_to = 'past_due' AND cur = 'active')
          OR (p_to = 'suspended' AND cur IN ('trial', 'active', 'past_due'));
    IF NOT legal THEN
        PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
        RETURN 'refused_transition';
    END IF;
    PERFORM pg_catalog.set_config('consentvault.status_cause', p_cause, true);
    PERFORM pg_catalog.set_config('consentvault.status_actor', 'stripe:' || p_event_id, true);
    UPDATE consentvault.organization SET status = p_to WHERE org_id = p_org;
    PERFORM pg_catalog.set_config('consentvault.status_cause', '', true);
    PERFORM pg_catalog.set_config('consentvault.status_actor', '', true);
    PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
    RETURN 'changed';
END;
$$;
REVOKE ALL ON FUNCTION consentvault.billing_apply_status(uuid, text, text, text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_apply_status(uuid, text, text, text, text[]) TO consentvault_app;

-- Usage: the worker's daily job, one organisation per transaction, inside its worker:usage token -----------------------
CREATE FUNCTION consentvault.usage_require_scope() RETURNS uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.current_org();
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault usage: no tenant entered' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT coalesce(consentvault.current_token_scopes() && ARRAY['worker:usage', 'admin'], false) THEN
        RAISE EXCEPTION 'consentvault usage: the token lacks the worker:usage scope' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN org;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_require_scope() FROM PUBLIC;

-- Events the current organisation received on one UTC day.
CREATE FUNCTION consentvault.usage_events_for_day(p_day date) RETURNS bigint
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    RETURN (SELECT count(*) FROM consentvault.event e
             WHERE e.org_id = org
               AND e.received_at >= (p_day::timestamp AT TIME ZONE 'UTC')
               AND e.received_at < ((p_day + 1)::timestamp AT TIME ZONE 'UTC'));
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_events_for_day(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_events_for_day(date) TO consentvault_app, consentvault_worker;

-- Record the day's count. A day already reported to Stripe keeps the count that was reported.
CREATE FUNCTION consentvault.usage_record_day(p_day date, p_events bigint, p_gate_checks bigint) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    IF p_day >= (now() AT TIME ZONE 'UTC')::date THEN
        RAISE EXCEPTION 'consentvault usage: day % is not closed yet', p_day USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO consentvault.usage_day (org_id, day, events, gate_checks) VALUES (org, p_day, p_events, p_gate_checks)
        ON CONFLICT (org_id, day) DO UPDATE SET events = excluded.events, gate_checks = excluded.gate_checks
        WHERE consentvault.usage_day.reported_at IS NULL AND consentvault.usage_day.stripe_ack = '{}'::jsonb;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_record_day(date, bigint, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_record_day(date, bigint, bigint) TO consentvault_app, consentvault_worker;

-- What the job needs to report one day: the held counts, what Stripe already acknowledged, and the Stripe customer.
CREATE FUNCTION consentvault.usage_target(p_day date)
    RETURNS TABLE (events bigint, gate_checks bigint, stripe_ack jsonb, stripe_customer_id text,
                   stripe_subscription_id text, subscription_status text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    RETURN QUERY
    SELECT u.events, u.gate_checks, u.stripe_ack, a.stripe_customer_id, a.stripe_subscription_id, a.status
      FROM consentvault.usage_day u
      LEFT JOIN consentvault.billing_account a ON a.org_id = u.org_id
     WHERE u.org_id = org AND u.day = p_day;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_target(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_target(date) TO consentvault_app, consentvault_worker;

-- Record Stripe's acknowledgement of one meter for one day; the day counts as reported when both meters are acknowledged.
CREATE FUNCTION consentvault.usage_mark_reported(p_day date, p_meter text, p_ack text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    IF p_meter NOT IN ('events', 'gate_checks') OR p_ack IS NULL OR length(p_ack) NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'consentvault usage: a meter (events or gate_checks) and a Stripe acknowledgement are required'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE consentvault.usage_day u
       SET stripe_ack = u.stripe_ack || jsonb_build_object(p_meter, p_ack),
           reported_at = CASE WHEN (u.stripe_ack || jsonb_build_object(p_meter, p_ack)) ?& ARRAY['events', 'gate_checks']
                              THEN now() ELSE u.reported_at END
     WHERE u.org_id = org AND u.day = p_day;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault usage: no count recorded for % on %', org, p_day USING ERRCODE = 'no_data_found';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_mark_reported(date, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_mark_reported(date, text, text) TO consentvault_app, consentvault_worker;

-- Trial and past_due organisations are live: capture is never refused for non-payment (billing contract) ---------------
-- The three lookups keep their owner and shape; only the set of statuses that count as live widens. Suspended,
-- offboarding and closed read as before.
CREATE OR REPLACE FUNCTION consentvault.resolve_credential(p_credential_id uuid)
    RETURNS TABLE (org_id uuid, scopes text[], public_key text, alg text, kind text, allowed_origins text[], status text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT c.org_id, c.scope, c.public_key, c.alg, c.kind, coalesce(s.allowed_origins, '{}'::text[]),
           CASE WHEN c.revoked_at IS NOT NULL THEN 'revoked'
                WHEN o.status NOT IN ('active', 'trial', 'past_due') THEN 'org_' || o.status
                ELSE 'active' END
    FROM consentvault.credential c
    JOIN consentvault.organization o ON o.org_id = c.org_id
    LEFT JOIN consentvault.capture_source s ON s.org_id = c.org_id AND s.source_id = c.source_id
    WHERE c.credential_id = p_credential_id;
$$;

CREATE OR REPLACE FUNCTION consentvault.resolve_member(p_idp_issuer text, p_idp_subject text)
    RETURNS TABLE (org_id uuid, role text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT m.org_id, m.role
    FROM consentvault.member m
    JOIN consentvault.organization o ON o.org_id = m.org_id
    WHERE m.idp_issuer = p_idp_issuer AND m.idp_subject = p_idp_subject
      AND o.status IN ('active', 'trial', 'past_due')
    ORDER BY m.org_id;
$$;

CREATE OR REPLACE FUNCTION consentvault.active_org_ids() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT org_id FROM consentvault.organization WHERE status IN ('active', 'trial', 'past_due') ORDER BY org_id;
$$;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
