-- Gate checks counted for usage billing.
--
-- gate_check_tally: one row per recorded gate decision, written by the gate in the same savepoint as the decision itself
-- (a decision that is not recorded is not counted and not answered). Tenant table: row-level security on current_org(),
-- append-only, no contact data. gate_decision itself cannot serve: its read policy admits read scopes only, so a worker
-- token would count zero rows and read as a quiet day.
-- gate_check_tally_start: the first UTC day the tally covers (one row, owner-only). usage_gate_checks_for_day(day)
-- answers NULL for a day before it, which the usage job reads as "no count", never as zero; a covered quiet day is a real 0.
-- billing_clear_alarm is narrowed to the one alarm the webhook clears for the app role: the duplicate-subscription alarm.

CREATE TABLE consentvault.gate_check_tally (
    org_id uuid NOT NULL REFERENCES consentvault.organization (org_id),
    seq    bigint GENERATED ALWAYS AS IDENTITY,
    day    date NOT NULL,
    at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, seq)
);
CREATE INDEX gate_check_tally_day_idx ON consentvault.gate_check_tally (org_id, day);
ALTER TABLE consentvault.gate_check_tally ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.gate_check_tally FORCE ROW LEVEL SECURITY;
CREATE POLICY gate_check_tally_tenant ON consentvault.gate_check_tally
    USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
GRANT INSERT (org_id, day) ON consentvault.gate_check_tally TO consentvault_app;
CREATE TRIGGER gate_check_tally_no_update BEFORE UPDATE ON consentvault.gate_check_tally
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER gate_check_tally_no_delete BEFORE DELETE ON consentvault.gate_check_tally
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER gate_check_tally_no_truncate BEFORE TRUNCATE ON consentvault.gate_check_tally
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

CREATE TABLE consentvault.gate_check_tally_start (
    only_row   boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    started_on date NOT NULL
);
REVOKE ALL ON consentvault.gate_check_tally_start FROM PUBLIC;
-- checks made before this migration were not counted: the first fully counted day is the next UTC day
INSERT INTO consentvault.gate_check_tally_start (started_on) VALUES (((now() AT TIME ZONE 'UTC')::date) + 1);

CREATE FUNCTION consentvault.usage_gate_checks_for_day(p_day date) RETURNS bigint
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org   uuid := consentvault.usage_require_scope();
    began date;
BEGIN
    SELECT s.started_on INTO began FROM consentvault.gate_check_tally_start s;
    IF began IS NULL OR p_day < began THEN
        RETURN NULL;
    END IF;
    RETURN (SELECT count(*) FROM consentvault.gate_check_tally t WHERE t.org_id = org AND t.day = p_day);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_gate_checks_for_day(date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_gate_checks_for_day(date) TO consentvault_worker;

CREATE OR REPLACE FUNCTION consentvault.billing_clear_alarm(p_org uuid, p_name text, p_by text) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    prev text := pg_catalog.current_setting('consentvault.org_token', true);
    n    integer;
BEGIN
    IF p_org IS NULL THEN
        RAISE EXCEPTION 'consentvault billing: an organisation is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_name IS DISTINCT FROM 'billing.second_live_subscription' THEN
        RAISE EXCEPTION 'consentvault billing: only the duplicate-subscription alarm is cleared here'
            USING ERRCODE = 'insufficient_privilege';
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
