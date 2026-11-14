-- Reverses 0035_system_test_grant.sql.
BEGIN;
DROP FUNCTION consentvault.system_test_record(uuid, jsonb);
DROP FUNCTION consentvault.system_test_begin(uuid);
DROP TABLE consentvault.system_test_attempt;
COMMIT;
