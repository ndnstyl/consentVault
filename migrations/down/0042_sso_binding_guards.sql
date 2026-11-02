-- Reverses 0042_sso_binding_guards.sql. Run it as the schema owner, in one transaction.
BEGIN;
DROP FUNCTION consentvault.sso_binding_check(text);
REVOKE SELECT (org_id, version, workos_org_id) ON consentvault.org_sso FROM consentvault_operator;
REVOKE EXECUTE ON FUNCTION consentvault.org_alarm_clear(text) FROM consentvault_console;
COMMIT;
