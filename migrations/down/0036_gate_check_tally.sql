-- Reverses 0036_gate_check_tally.sql. Refuses while any tally row exists: the tally is what usage was billed on and a
-- down migration never destroys it. billing_clear_alarm returns as 0032 shipped it.
-- Run it as a superuser (or a BYPASSRLS role), in one transaction.
BEGIN;

DO $$
BEGIN
    IF to_regclass('consentvault.gate_check_tally') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0036 refused: 0036 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.gate_check_tally) THEN
        RAISE EXCEPTION 'consentvault down 0036 refused: gate check tally rows exist and are never destroyed';
    END IF;
END
$$;

DROP FUNCTION consentvault.usage_gate_checks_for_day(date);
DROP TABLE consentvault.gate_check_tally_start;
DROP TABLE consentvault.gate_check_tally;

CREATE OR REPLACE FUNCTION consentvault.billing_clear_alarm(p_org uuid, p_name text, p_by text) RETURNS integer
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

COMMIT;
