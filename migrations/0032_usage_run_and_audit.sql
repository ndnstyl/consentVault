-- Usage jobs made safe to schedule:
--
-- usage_run: the daily run's heartbeat (platform table, owner-only). The retry pass reads its age and goes red when no
-- daily run has finished in 26 hours. usage_run_finish(day) is called when a run completes (whatever its per-organisation
-- failures, each of which alarms by name); usage_run_age(at) is NULL when no run has ever finished.
-- usage_acknowledge_verdict replaces usage_acknowledge: worker role only, a verdict is acknowledged once (a second attempt
-- is refused), and every acknowledgement leaves an append-only audit row naming who made it.
-- usage_schedule_retry(day): schedule the retry without touching a send mark (for a failed resend of a mark an earlier
-- attempt made, which may have been accepted).
-- billing_clear_alarm(org, name, by): acknowledge the organisation's open alarm of that name (the duplicate-subscription
-- alarm clears when the second subscription ends).

CREATE TABLE consentvault.usage_run (
    job         text PRIMARY KEY CHECK (job = 'daily'),
    day         date NOT NULL,
    finished_at timestamptz NOT NULL
);
REVOKE ALL ON consentvault.usage_run FROM PUBLIC;

CREATE FUNCTION consentvault.usage_run_finish(p_day date) RETURNS void
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO consentvault.usage_run (job, day, finished_at) VALUES ('daily', p_day, clock_timestamp())
        ON CONFLICT (job) DO UPDATE SET day = excluded.day, finished_at = excluded.finished_at;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_run_finish(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_run_finish(date) TO consentvault_worker;

CREATE FUNCTION consentvault.usage_run_age(p_at timestamptz) RETURNS double precision
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT extract(epoch FROM p_at - r.finished_at) FROM consentvault.usage_run r WHERE r.job = 'daily';
$$;
REVOKE ALL ON FUNCTION consentvault.usage_run_age(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_run_age(timestamptz) TO consentvault_worker;

CREATE TABLE consentvault.usage_verdict_audit (
    org_id          uuid NOT NULL REFERENCES consentvault.organization (org_id),
    seq             bigint GENERATED ALWAYS AS IDENTITY,
    day             date NOT NULL,
    key             text NOT NULL CHECK (length(key) BETWEEN 1 AND 60),
    acknowledged_by text NOT NULL CHECK (length(acknowledged_by) BETWEEN 1 AND 200),
    acknowledged_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, seq)
);
ALTER TABLE consentvault.usage_verdict_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.usage_verdict_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY usage_verdict_audit_tenant ON consentvault.usage_verdict_audit
    USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
GRANT SELECT ON consentvault.usage_verdict_audit TO consentvault_app;
CREATE TRIGGER usage_verdict_audit_no_update BEFORE UPDATE ON consentvault.usage_verdict_audit
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER usage_verdict_audit_no_delete BEFORE DELETE ON consentvault.usage_verdict_audit
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER usage_verdict_audit_no_truncate BEFORE TRUNCATE ON consentvault.usage_verdict_audit
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

DROP FUNCTION consentvault.usage_acknowledge(date, text, text);

CREATE FUNCTION consentvault.usage_acknowledge_verdict(p_day date, p_key text, p_by text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
    cur jsonb;
BEGIN
    IF p_by IS NULL OR length(p_by) NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'consentvault usage: an acknowledgement names who made it' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT u.stripe_verdict -> p_key INTO cur
      FROM consentvault.usage_day u WHERE u.org_id = org AND u.day = p_day FOR UPDATE;
    IF NOT FOUND OR cur IS NULL THEN
        RAISE EXCEPTION 'consentvault usage: no verdict % on % for %', p_key, p_day, org USING ERRCODE = 'no_data_found';
    END IF;
    IF coalesce((cur ->> 'acknowledged')::boolean, false) THEN
        RAISE EXCEPTION 'consentvault usage: verdict % on % is already acknowledged', p_key, p_day
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    UPDATE consentvault.usage_day u
       SET stripe_verdict = jsonb_set(u.stripe_verdict, ARRAY[p_key],
             cur || jsonb_build_object('acknowledged', true, 'by', p_by, 'acknowledged_at', clock_timestamp()))
     WHERE u.org_id = org AND u.day = p_day;
    INSERT INTO consentvault.usage_verdict_audit (org_id, day, key, acknowledged_by) VALUES (org, p_day, p_key, p_by);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_acknowledge_verdict(date, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_acknowledge_verdict(date, text, text) TO consentvault_worker;

CREATE FUNCTION consentvault.usage_schedule_retry(p_day date) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    UPDATE consentvault.usage_day u SET retry_at = clock_timestamp() + interval '1 hour'
     WHERE u.org_id = org AND u.day = p_day AND u.reported_at IS NULL;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_schedule_retry(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_schedule_retry(date) TO consentvault_app, consentvault_worker;

CREATE FUNCTION consentvault.billing_clear_alarm(p_org uuid, p_name text, p_by text) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    prev text := pg_catalog.current_setting('consentvault.org_token', true);
    n    integer;
BEGIN
    IF p_org IS NULL THEN
        RAISE EXCEPTION 'consentvault billing: an organisation is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_catalog.set_config('consentvault.org_token',
                                  consentvault.sign_org_token(p_org, ARRAY['billing'], NULL, 60), true);
    UPDATE consentvault.operator_alarm a SET acknowledged_at = clock_timestamp(), acknowledged_by = p_by
     WHERE a.org_id = p_org AND a.name = p_name AND a.acknowledged_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
    RETURN n;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.billing_clear_alarm(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_clear_alarm(uuid, text, text) TO consentvault_app;
