-- Why an organisation is suspended, and who may lift it. A suspension that came from the Stripe subscription ending
-- (cause subscription_deleted) records reason 'subscription_canceled' and a paid invoice may lift it. Every other
-- suspension (an operator's: abuse, legal hold, a DBA's change) records 'operator' and only an operator action lifts
-- it: a webhook answers refused_operator_suspension. Any status other than suspended carries no reason.

ALTER TABLE consentvault.organization
    ADD COLUMN suspension_reason text CHECK (suspension_reason IN ('subscription_canceled', 'operator')),
    ADD CONSTRAINT organization_suspension_reason_only_when_suspended
        CHECK ((status = 'suspended') = (suspension_reason IS NOT NULL)) NOT VALID;

-- Organisations already suspended before this migration: nothing says why, so an operator must lift them.
UPDATE consentvault.organization SET suspension_reason = 'operator' WHERE status = 'suspended';
ALTER TABLE consentvault.organization VALIDATE CONSTRAINT organization_suspension_reason_only_when_suspended;

CREATE FUNCTION consentvault.organization_suspension_reason() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    cause text := coalesce(pg_catalog.current_setting('consentvault.status_cause', true), '');
BEGIN
    IF NEW.status <> 'suspended' THEN
        NEW.suspension_reason := NULL;
    ELSIF cause = 'subscription_deleted' THEN
        -- the subscription ending never overrides an operator's suspension already in force
        NEW.suspension_reason := CASE WHEN TG_OP = 'UPDATE' AND OLD.status = 'suspended'
                                      THEN coalesce(OLD.suspension_reason, 'operator') ELSE 'subscription_canceled' END;
    ELSE
        NEW.suspension_reason := 'operator';  -- any other suspension is an operator's, and stays until an operator lifts it
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER organization_suspension_reason BEFORE INSERT OR UPDATE OF status, suspension_reason
    ON consentvault.organization FOR EACH ROW EXECUTE FUNCTION consentvault.organization_suspension_reason();

CREATE OR REPLACE FUNCTION consentvault.billing_apply_status(
    p_org uuid, p_to text, p_cause text, p_event_id text, p_only_from text[] DEFAULT NULL) RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    prev   text := pg_catalog.current_setting('consentvault.org_token', true);
    cur    text;
    why    text;
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
    SELECT status, suspension_reason INTO cur, why FROM consentvault.organization WHERE org_id = p_org FOR UPDATE;
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
    IF p_to = 'active' AND cur = 'suspended' AND why IS DISTINCT FROM 'subscription_canceled' THEN
        PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
        RETURN 'refused_operator_suspension';
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
