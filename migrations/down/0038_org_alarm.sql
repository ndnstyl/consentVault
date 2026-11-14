-- Reverses 0038_org_alarm.sql: the clear function, then the table (its index, policy and grants go with it).
BEGIN;
DROP FUNCTION consentvault.org_alarm_clear(text);
DROP TABLE consentvault.org_alarm;
COMMIT;
