-- Reverses 0026_rds_master_allowance.sql. Run it as a superuser (the trigger guard refuses changes to pinned guards for
-- anyone else), in one transaction. The console-member clause follows every membership again, admin-only ones included.
-- The pins are cleared: a superuser re-pins after the next migration run.
BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'owner_rights_violations'
                    AND pronamespace = 'consentvault'::regnamespace AND prosrc LIKE '%by an INHERIT or SET membership%') THEN
        RAISE EXCEPTION 'consentvault down 0026 refused: 0026 is not applied';
    END IF;
    IF to_regclass('consentvault_guard.pin') IS NOT NULL THEN
        DELETE FROM consentvault_guard.pin;
    END IF;
    IF to_regclass('consentvault_guard.table_pin') IS NOT NULL THEN
        DELETE FROM consentvault_guard.table_pin;
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION consentvault.owner_rights_violations()
    RETURNS TABLE (object_kind text, object_name text, owner_name text, problem text)
    LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RETURN QUERY SELECT v.k::text, v.n::text, v.o::text, v.p::text FROM (
    WITH RECURSIVE ns AS (
        SELECT n.oid, n.nspowner FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.=) 'consentvault'
    ), op AS (
        SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) 'consentvault_operator'
    ), breakglass AS (
        SELECT r.oid FROM pg_catalog.pg_roles r
         WHERE r.rolsuper
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles g WHERE g.rolname OPERATOR(pg_catalog.=) 'rds_superuser'
                        AND pg_catalog.pg_has_role(r.oid, g.oid, 'MEMBER'))
    ), guard(evtname, evtevent, fn) AS (
        VALUES ('consentvault_refuse_trigger_drop'::name, 'sql_drop'::name, 'refuse_trigger_drop'::name),
               ('consentvault_refuse_trigger_disable'::name, 'ddl_command_end'::name, 'refuse_trigger_disable'::name),
               ('consentvault_refuse_guard_change'::name, 'ddl_command_end'::name, 'refuse_guard_change'::name),
               ('consentvault_refuse_policy_change'::name, 'ddl_command_end'::name, 'refuse_policy_change'::name),
               ('consentvault_refuse_vault_child_change'::name, 'ddl_command_end'::name,
                'refuse_vault_child_change'::name)
    ), console_members(oid) AS (
        SELECT m.member FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles c ON c.oid OPERATOR(pg_catalog.=) m.roleid
         WHERE c.rolname OPERATOR(pg_catalog.=) 'consentvault_console'
        UNION
        SELECT m.member FROM pg_catalog.pg_auth_members m JOIN console_members x ON m.roleid OPERATOR(pg_catalog.=) x.oid
    )
    SELECT 'schema', 'consentvault', r.rolname, 'the schema owner is a superuser or BYPASSRLS'
      FROM ns JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) ns.nspowner
     WHERE r.rolsuper OR r.rolbypassrls
    UNION ALL
    SELECT 'schema', 'consentvault', r.rolname,
           'the schema owner can log in; it must be NOLOGIN (migrations connect as a member and SET ROLE to it)'
      FROM ns JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) ns.nspowner
     WHERE r.rolcanlogin
    UNION ALL
    SELECT 'role', 'consentvault_operator', r.rolname, 'the operator role is a superuser'
      FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) 'consentvault_operator' AND r.rolsuper
    UNION ALL
    SELECT 'role', 'consentvault_console', r.rolname,
           'the operator console role is a superuser or BYPASSRLS, or a member of the schema owner'
      FROM pg_catalog.pg_roles r, ns
     WHERE r.rolname OPERATOR(pg_catalog.=) 'consentvault_console'
       AND (r.rolsuper OR r.rolbypassrls OR pg_catalog.pg_has_role(r.oid, ns.nspowner, 'MEMBER'))
    UNION ALL
    SELECT 'role', r.rolname::text, r.rolname::text,
           'a member of consentvault_console is a superuser, the schema owner or a member of it, or a member of a '
           'BYPASSRLS role; the operator console would act outside row security'
      FROM console_members cm JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) cm.oid, ns
     WHERE r.rolsuper OR r.oid OPERATOR(pg_catalog.=) ns.nspowner OR pg_catalog.pg_has_role(r.oid, ns.nspowner, 'MEMBER')
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles b
                    WHERE b.rolbypassrls AND pg_catalog.pg_has_role(r.oid, b.oid, 'MEMBER'))
    UNION ALL
    SELECT 'function', p.oid::pg_catalog.regprocedure::pg_catalog.text, r.rolname,
           'an owner-rights function is owned by a role other than the schema owner or consentvault_operator'
      FROM pg_catalog.pg_proc p
      JOIN ns ON p.pronamespace OPERATOR(pg_catalog.=) ns.oid
      JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) p.proowner
     WHERE p.proowner OPERATOR(pg_catalog.<>) ns.nspowner
       AND p.proowner OPERATOR(pg_catalog.<>) ALL (ARRAY(SELECT oid FROM op))
    UNION ALL
    SELECT 'table', c.oid::pg_catalog.regclass::pg_catalog.text, r.rolname,
           'a row-secured table is owned by a superuser or BYPASSRLS role, or does not FORCE row-level security'
      FROM pg_catalog.pg_class c
      JOIN ns ON c.relnamespace OPERATOR(pg_catalog.=) ns.oid
      JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) c.relowner
     WHERE c.relkind IN ('r', 'p') AND c.relrowsecurity
       AND (r.rolsuper OR r.rolbypassrls OR NOT c.relforcerowsecurity)
    UNION ALL
    SELECT 'relation', c.oid::pg_catalog.regclass::pg_catalog.text, r.rolname,
           'a table, view or sequence is owned by a role other than the schema owner'
      FROM pg_catalog.pg_class c
      JOIN ns ON c.relnamespace OPERATOR(pg_catalog.=) ns.oid
      JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) c.relowner
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND c.relowner OPERATOR(pg_catalog.<>) ns.nspowner
    UNION ALL
    SELECT 'event trigger', g.evtname::pg_catalog.text, coalesce(pg_catalog.pg_get_userbyid(e.evtowner), '-'),
           'the trigger guard is missing, disabled, not on its event, or not owned by a superuser '
           '(run docker/initdb/20-trigger-guard.sql as a superuser)'
      FROM guard g
      LEFT JOIN pg_catalog.pg_event_trigger e ON e.evtname OPERATOR(pg_catalog.=) g.evtname
      LEFT JOIN pg_catalog.pg_proc p ON p.oid OPERATOR(pg_catalog.=) e.evtfoid
      LEFT JOIN pg_catalog.pg_namespace pn ON pn.oid OPERATOR(pg_catalog.=) p.pronamespace
     WHERE e.oid IS NULL OR e.evtenabled OPERATOR(pg_catalog.=) 'D' OR e.evtevent OPERATOR(pg_catalog.<>) g.evtevent
        OR pn.nspname IS DISTINCT FROM 'consentvault_guard' OR p.proname IS DISTINCT FROM g.fn
        OR e.evtowner OPERATOR(pg_catalog.<>) ALL (ARRAY(SELECT oid FROM breakglass))
        OR p.proowner OPERATOR(pg_catalog.<>) ALL (ARRAY(SELECT oid FROM breakglass))
        OR pn.nspowner OPERATOR(pg_catalog.<>) ALL (ARRAY(SELECT oid FROM breakglass))
    ) v (k, n, o, p);
    IF to_regprocedure('consentvault_guard.pin_violations()') IS NULL THEN
        RETURN QUERY SELECT 'event trigger'::text, 'consentvault_guard.pin_violations()'::text, '-'::text,
            'the trigger guard predates guard pinning: run docker/initdb/20-trigger-guard.sql again as a superuser, then '
            'SELECT consentvault_guard.pin_guards()'::text;
    ELSE
        RETURN QUERY EXECUTE 'SELECT object_kind, object_name, owner_name, problem FROM consentvault_guard.pin_violations()';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.owner_rights_violations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.owner_rights_violations() TO consentvault_app, consentvault_worker,
    consentvault_console;



COMMIT;
