-- Reverses 0010_operator_alarm.sql. Refuses while any alarm exists: an alarm is a record of a failure and a down
-- migration never destroys it.
-- Run it as a superuser (or a BYPASSRLS role), in one transaction.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regclass('consentvault.operator_alarm') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0010 refused: consentvault.operator_alarm is missing; 0010 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.operator_alarm) THEN
        RAISE EXCEPTION 'consentvault down 0010 refused: the vault holds operator alarms';
    END IF;
END
$$;

DROP TABLE consentvault.operator_alarm;
DROP FUNCTION consentvault.operator_alarm_guard();

COMMIT;
