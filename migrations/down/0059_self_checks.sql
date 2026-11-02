-- Undo 0059: the drill record and the canary pair are dropped with their functions, and both groups lose every grant 0059
-- gave them. The roles themselves (made by a superuser) are left in place. A canary organisation already made stays a
-- closed organisation with no keys and no evidence.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT c.oid::regclass AS rel FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'consentvault' AND c.relkind IN ('r', 'p', 'v')
               AND pg_catalog.has_table_privilege('consentvault_isolation_self_test', c.oid, 'SELECT') LOOP
        EXECUTE pg_catalog.format('REVOKE SELECT ON %s FROM consentvault_isolation_self_test', r.rel);
    END LOOP;
    FOR r IN SELECT p.oid::regprocedure AS fn FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'consentvault' AND EXISTS (
                 SELECT 1 FROM pg_catalog.aclexplode(p.proacl) x
                  WHERE x.grantee = 'consentvault_isolation_self_test'::regrole AND x.privilege_type = 'EXECUTE') LOOP
        EXECUTE pg_catalog.format('REVOKE EXECUTE ON FUNCTION %s FROM consentvault_isolation_self_test', r.fn);
    END LOOP;
END
$$;
REVOKE USAGE ON SCHEMA consentvault FROM consentvault_isolation_self_test, consentvault_restore_drill;

DROP FUNCTION consentvault.restore_drill_runs(integer);
DROP FUNCTION consentvault.record_restore_drill(text, timestamptz, timestamptz, timestamptz, integer, text, integer, jsonb);
DROP TABLE consentvault.restore_drill_run;
DROP FUNCTION consentvault.restore_drill_run_frozen();

DROP FUNCTION consentvault.isolation_self_test_grant_reads();
DROP FUNCTION consentvault.isolation_canary_token(text);
DROP FUNCTION consentvault.isolation_canary_pair();
DROP TABLE consentvault.isolation_canary;
DROP FUNCTION consentvault.isolation_canary_frozen();
