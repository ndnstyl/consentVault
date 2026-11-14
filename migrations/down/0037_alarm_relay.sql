-- Reverses 0037_alarm_relay.sql: the relay functions and the relayed mark go; the guard again allows only the
-- acknowledgement. Run it as a superuser (or a BYPASSRLS role), in one transaction.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regclass('consentvault.operator_alarm') IS NULL OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema = 'consentvault' AND table_name = 'operator_alarm'
           AND column_name = 'relayed_at') THEN
        RAISE EXCEPTION 'consentvault down 0037 refused: 0037 is not applied';
    END IF;
END
$$;

DROP FUNCTION consentvault.alarm_relay_mark(uuid, uuid);
DROP FUNCTION consentvault.alarm_relay_pending(integer);
REVOKE UPDATE (relayed_at) ON consentvault.operator_alarm FROM consentvault_operator;
ALTER TABLE consentvault.operator_alarm DROP COLUMN relayed_at;

CREATE OR REPLACE FUNCTION consentvault.operator_alarm_guard() RETURNS trigger
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
COMMIT;
