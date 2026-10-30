-- Final guards of the checkpoint: pinned trigger guards, the operator console's members, key versions kept for backups,
-- and a rotation that offboarding cancels.
--
-- 1. owner_rights_violations() (the API's start check) now also requires the third trigger-guard event trigger
--    (consentvault_refuse_guard_change), reports every member of consentvault_console that is a superuser, the schema
--    owner or a member of it, or a member of any BYPASSRLS role, and reports every pinned guard that changed, is gone, or
--    is not pinned (consentvault_guard.pin_violations(), from docker/initdb/20-trigger-guard.sql). A trigger guard
--    installed before pinning existed is reported until it is re-run as a superuser.
-- 2. A retired key version is kept as 'retained_for_backup' until the oldest database backup that may still hold keys
--    wrapped under it ages out (the backup retention setting); the key rotation job destroys it then.
-- 3. A key rotation may end 'cancelled' (offboarding cancels an open rotation before it proceeds), with the time and
--    reason on the record. Cancelled is final, like complete; only an open rotation (rewrapping or blocked) blocks a new one.
-- 4. Last: every guard function and guarded trigger is pinned (insert-only) when the guard schema offers pinning.

DO $$
BEGIN
    IF to_regclass('consentvault.key_rotation') IS NULL THEN
        RAISE EXCEPTION 'consentvault migration 0023 refused: 0020 (key rotation) is not applied';
    END IF;
END
$$;

-- 2. Key versions kept for backups ------------------------------------------------------------------------------------------
ALTER TABLE consentvault.org_key DROP CONSTRAINT org_key_status_check;
ALTER TABLE consentvault.org_key ADD CONSTRAINT org_key_status_check
    CHECK (status IN ('active', 'retired', 'retained_for_ledger', 'retained_for_backup', 'scheduled_destroy', 'destroyed'));
ALTER TABLE consentvault.org_key DROP CONSTRAINT org_key_pre_schedule_status_check;
ALTER TABLE consentvault.org_key ADD CONSTRAINT org_key_pre_schedule_status_check
    CHECK (pre_schedule_status IS NULL OR pre_schedule_status IN ('active', 'retired', 'retained_for_ledger',
                                                                  'retained_for_backup'));
ALTER TABLE consentvault.org_key DROP CONSTRAINT org_key_retained_shape;
ALTER TABLE consentvault.org_key ADD CONSTRAINT org_key_retained_shape
    CHECK (status NOT IN ('retained_for_ledger', 'retained_for_backup') OR destroy_after IS NOT NULL);

CREATE OR REPLACE FUNCTION consentvault.org_key_version_guard() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    left_over text;
BEGIN
    IF OLD.status IN ('retired', 'retained_for_ledger', 'retained_for_backup')
       AND NEW.status IN ('retained_for_ledger', 'retained_for_backup', 'destroyed')
       AND NEW.status IS DISTINCT FROM OLD.status THEN
        IF consentvault.current_org() IS DISTINCT FROM NEW.org_id THEN
            RAISE EXCEPTION 'consentvault.org_key: a key version is destroyed only inside its own organization'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        SELECT string_agg(c.kind || '=' || c.n, ', ') INTO left_over
          FROM consentvault.key_version_census_of(NEW.org_id, NEW.version) c WHERE c.n > 0;
        IF left_over IS NOT NULL THEN
            RAISE EXCEPTION 'key_version_in_use: version % still wraps %', NEW.version, left_over
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    IF OLD.status = 'destroyed' AND NEW.status IS DISTINCT FROM 'destroyed' THEN
        RAISE EXCEPTION 'consentvault.org_key: a destroyed key version stays destroyed' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- 3. A cancelled rotation -----------------------------------------------------------------------------------------------------
ALTER TABLE consentvault.key_rotation
    ADD COLUMN cancelled_at  timestamptz,
    ADD COLUMN cancel_reason text CHECK (cancel_reason IS NULL OR length(cancel_reason) BETWEEN 1 AND 500);
ALTER TABLE consentvault.key_rotation DROP CONSTRAINT key_rotation_status_check;
ALTER TABLE consentvault.key_rotation ADD CONSTRAINT key_rotation_status_check
    CHECK (status IN ('rewrapping', 'blocked', 'complete', 'cancelled'));
ALTER TABLE consentvault.key_rotation ADD CONSTRAINT key_rotation_cancelled_shape
    CHECK ((status = 'cancelled') = (cancelled_at IS NOT NULL) AND (cancelled_at IS NULL) = (cancel_reason IS NULL));
DROP INDEX consentvault.key_rotation_one_open_idx;
CREATE UNIQUE INDEX key_rotation_one_open_idx ON consentvault.key_rotation (org_id)
    WHERE status NOT IN ('complete', 'cancelled');

CREATE OR REPLACE FUNCTION consentvault.key_rotation_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.key_rotation is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status IN ('complete', 'cancelled') THEN
        RAISE EXCEPTION 'consentvault.key_rotation: a % rotation does not change', OLD.status
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.org_id, NEW.rotation_id, NEW.from_version, NEW.to_version, NEW.reason, NEW.started_by, NEW.started_at)
       IS DISTINCT FROM (OLD.org_id, OLD.rotation_id, OLD.from_version, OLD.to_version, OLD.reason, OLD.started_by,
                         OLD.started_at)
       OR NEW.rewrapped < OLD.rewrapped OR NEW.batches < OLD.batches THEN
        RAISE EXCEPTION 'consentvault.key_rotation: only the progress and state of a rotation change, forward'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

GRANT UPDATE (cancelled_at, cancel_reason) ON consentvault.key_rotation TO consentvault_console;

-- 1. The start check ----------------------------------------------------------------------------------------------------------
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
               ('consentvault_refuse_guard_change'::name, 'ddl_command_end'::name, 'refuse_guard_change'::name)
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

-- 4. Pin the guards (last, so this migration's own replacements are what is pinned) ----------------------------------------
DO $$
BEGIN
    -- pinning is a superuser's (the trigger guard as of migration 0024); the migrator's run leaves it to the deployment
    IF to_regprocedure('consentvault_guard.pin_guards()') IS NOT NULL
       AND has_function_privilege('consentvault_guard.pin_guards()', 'EXECUTE') THEN
        PERFORM consentvault_guard.pin_guards();
    END IF;
END
$$;
