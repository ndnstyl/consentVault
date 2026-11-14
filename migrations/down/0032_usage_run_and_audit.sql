-- Reverses 0032_usage_run_and_audit.sql. Refuses while any acknowledgement audit row exists: an audit row is a record of
-- who cleared a verdict and a down migration never destroys it. The run heartbeat goes with its table; usage_acknowledge
-- returns as 0031 shipped it.
-- Run it as a superuser (or a BYPASSRLS role), in one transaction.
BEGIN;

DO $$
BEGIN
    IF to_regclass('consentvault.usage_run') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0032 refused: 0032 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.usage_verdict_audit) THEN
        RAISE EXCEPTION 'consentvault down 0032 refused: acknowledgement audit rows exist and are never destroyed';
    END IF;
END
$$;

DROP FUNCTION consentvault.billing_clear_alarm(uuid, text, text);
DROP FUNCTION consentvault.usage_schedule_retry(date);
DROP FUNCTION consentvault.usage_acknowledge_verdict(date, text, text);
DROP TABLE consentvault.usage_verdict_audit;
DROP FUNCTION consentvault.usage_run_age(timestamptz);
DROP FUNCTION consentvault.usage_run_finish(date);
DROP TABLE consentvault.usage_run;

CREATE FUNCTION consentvault.usage_acknowledge(p_day date, p_key text, p_by text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    IF p_by IS NULL OR length(p_by) NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'consentvault usage: an acknowledgement names who made it' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE consentvault.usage_day u
       SET stripe_verdict = jsonb_set(u.stripe_verdict, ARRAY[p_key],
             (u.stripe_verdict -> p_key) || jsonb_build_object('acknowledged', true, 'by', p_by,
                                                               'acknowledged_at', clock_timestamp()))
     WHERE u.org_id = org AND u.day = p_day AND u.stripe_verdict ? p_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault usage: no verdict % on % for %', p_key, p_day, org USING ERRCODE = 'no_data_found';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_acknowledge(date, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_acknowledge(date, text, text) TO consentvault_app, consentvault_worker;

COMMIT;
