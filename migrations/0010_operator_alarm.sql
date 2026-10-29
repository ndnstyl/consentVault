-- Operator alarms: a failure the request path cannot answer by itself (for example, a release decision that could not
-- be written after the grant was recorded) leaves a row here, not only a server log line. Tenant table: row-level
-- security on current_org(), so the runtime role raises an alarm only for the organisation its token entered. The
-- operator (BYPASSRLS) reads every alarm and acknowledges it; the row carries no personal field (names, ids, an error
-- class), and nothing is ever deleted.

CREATE TABLE consentvault.operator_alarm (
    org_id          uuid NOT NULL REFERENCES consentvault.organization (org_id),
    alarm_id        uuid NOT NULL DEFAULT gen_random_uuid(),
    name            text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]{0,40}(\.[a-z][a-z0-9_]{0,40}){0,3}$'),
    ref_kind        text CHECK (ref_kind ~ '^[a-z][a-z0-9_]{0,40}$'),
    ref_id          uuid,
    error_class     text NOT NULL CHECK (error_class ~ '^[A-Za-z][A-Za-z0-9_]{0,80}$'),
    request_id      text CHECK (length(request_id) BETWEEN 1 AND 200),
    raised_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    acknowledged_at timestamptz,
    acknowledged_by text CHECK (length(acknowledged_by) BETWEEN 1 AND 200),
    PRIMARY KEY (org_id, alarm_id),
    CONSTRAINT operator_alarm_ref_pair CHECK ((ref_kind IS NULL) = (ref_id IS NULL)),
    CONSTRAINT operator_alarm_ack_pair CHECK ((acknowledged_at IS NULL) = (acknowledged_by IS NULL))
);
CREATE INDEX operator_alarm_open_idx ON consentvault.operator_alarm (raised_at) WHERE acknowledged_at IS NULL;

-- Append-only, except the one acknowledgement: nothing else changes, and an acknowledged alarm stays acknowledged.
CREATE FUNCTION consentvault.operator_alarm_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.acknowledged_at IS NOT NULL
       OR NEW.acknowledged_at IS NULL
       OR (NEW.org_id, NEW.alarm_id, NEW.name, NEW.ref_kind, NEW.ref_id, NEW.error_class, NEW.request_id, NEW.raised_at)
          IS DISTINCT FROM
          (OLD.org_id, OLD.alarm_id, OLD.name, OLD.ref_kind, OLD.ref_id, OLD.error_class, OLD.request_id, OLD.raised_at)
    THEN
        RAISE EXCEPTION 'consentvault: an operator alarm is only ever acknowledged, once'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER operator_alarm_ack_only BEFORE UPDATE ON consentvault.operator_alarm
    FOR EACH ROW EXECUTE FUNCTION consentvault.operator_alarm_guard();
CREATE TRIGGER operator_alarm_no_delete BEFORE DELETE ON consentvault.operator_alarm
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER operator_alarm_no_truncate BEFORE TRUNCATE ON consentvault.operator_alarm
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

ALTER TABLE consentvault.operator_alarm ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.operator_alarm FORCE ROW LEVEL SECURITY;
CREATE POLICY operator_alarm_tenant ON consentvault.operator_alarm
    USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));

REVOKE ALL ON consentvault.operator_alarm FROM PUBLIC;
GRANT INSERT (org_id, name, ref_kind, ref_id, error_class, request_id) ON consentvault.operator_alarm
    TO consentvault_app, consentvault_worker;
GRANT SELECT, UPDATE (acknowledged_at, acknowledged_by) ON consentvault.operator_alarm TO consentvault_operator;
