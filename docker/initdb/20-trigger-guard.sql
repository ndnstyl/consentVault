-- The trigger guard. Run once per database, AS A SUPERUSER (Docker runs it after 10-roles.sh when the volume is first
-- created; a managed database runs it as the master user, see docs/deployment.md). Safe to run again.
--
-- The vault's guarantees (append-only ledgers, legal holds, request states) are triggers on tables in the consentvault
-- schema. A table's owner can normally switch a trigger off (ALTER TABLE ... DISABLE TRIGGER, or ENABLE REPLICA, which
-- stops it firing in a normal session) or drop it. These two event triggers refuse both for every role that is not a
-- superuser: the migrator acting as the schema owner, the operator console and the runtime roles alike. A down
-- migration that must drop a trigger runs as a superuser, which is the only break-glass.
--
-- A third event trigger closes the ways around a guard the schema owner still had: replacing a guard function's body
-- (CREATE OR REPLACE FUNCTION, ALTER FUNCTION), replacing or renaming a guarded trigger (CREATE OR REPLACE TRIGGER,
-- ALTER TRIGGER), renaming the schema (ALTER SCHEMA consentvault) and moving or renaming a guarded table (ALTER TABLE
-- ... SET SCHEMA / RENAME), after which the name-based checks no longer saw it. Which objects are guards is pinned: the
-- table consentvault_guard.pin holds a SHA-256 of each guard function's definition (every trigger function of a vault
-- table, every vault function those call by name, and the start check itself) and of each guarded trigger's
-- definition. Pinning is insert-only for everyone (consentvault_guard.pin_guards(), which every migration that adds a
-- trigger calls); re-pinning a changed guard is a superuser's (consentvault_guard.repin()). A mismatch, a missing
-- pinned object or an unpinned guard is reported by consentvault_guard.pin_violations(), which the API reads at start
-- and refuses on.
--
-- Row security is a guard too. A restrictive policy, a dropped tenant policy or row security switched off on a table a
-- guard reads (the holds table, the key tables, the erasure tables) blinds the guard without touching it: the hold
-- lookup sees no hold and the held key is deleted. Every table a guard trigger is on, and every vault table a guard
-- function names, is pinned too (consentvault_guard.table_pin: its row security flags and a SHA-256 of every policy on
-- it), and a fourth event trigger refuses, for every role that is not a superuser, CREATE / ALTER / DROP POLICY on it
-- and ALTER TABLE ... ENABLE / DISABLE / FORCE / NO FORCE ROW LEVEL SECURITY that changes its pinned flags.
-- Pinning is a superuser's only (pin_guards() checks the session and is not executable by PUBLIC): the schema owner
-- cannot pin a trigger it just added. The deployment runs SELECT consentvault_guard.pin_guards() as the superuser (or
-- the managed service's master user) after every migration run. What the API finally compares against is the security
-- manifest built from a clean apply of the shipped migrations (src/consentvault/data/security_manifest.sha256): a pin
-- records what a superuser blessed, the manifest records what shipped.
--
-- A vault table's partitions and inheritance children are guarded too. A partition moved out of the vault schema left
-- the name-based checks behind (its append-only trigger could be switched off there and the partition moved back), and a
-- table in another schema inheriting from a vault table added rows the parent shows. Every child of a vault table, in any
-- schema, is recorded (consentvault_guard.child: its parent, schema and name, as CREATE TABLE ... PARTITION OF made it in
-- the vault schema), and a fifth event trigger refuses, for every role that is not a superuser: a child made or moved
-- outside the vault schema, a recorded child renamed, moved, detached (DETACH PARTITION) or un-inherited (NO INHERIT),
-- and a table attached to a vault table by ALTER TABLE (INHERIT, ATTACH PARTITION). The trigger-disable and guard-change
-- checks resolve a child to its vault root, in whatever schema it sits.
--
-- Everything lives in the schema consentvault_guard, owned by the superuser that runs this file, so the schema owner
-- (which owns the database) can neither replace nor drop the functions. Only a superuser can alter or drop an event
-- trigger. consentvault.owner_rights_violations() reports a missing or disabled guard, and the multi-tenant API refuses
-- to start while it does.
CREATE SCHEMA IF NOT EXISTS consentvault_guard;
REVOKE ALL ON SCHEMA consentvault_guard FROM PUBLIC;
GRANT USAGE ON SCHEMA consentvault_guard TO PUBLIC;

-- True when the session may change vault triggers: a superuser, or on a managed service (no true superuser) a member
-- of rds_superuser, which is the master user.
CREATE OR REPLACE FUNCTION consentvault_guard.break_glass() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                    WHERE r.rolname OPERATOR(pg_catalog.=) ANY (ARRAY[session_user, current_user]::name[]) AND r.rolsuper)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles g WHERE g.rolname OPERATOR(pg_catalog.=) 'rds_superuser'
                    AND pg_catalog.pg_has_role(session_user, g.oid, 'MEMBER'));
$$;

-- Any trigger on a consentvault table dropped by any command (DROP TRIGGER, DROP FUNCTION ... CASCADE, DROP TABLE).
-- Constraint triggers PostgreSQL makes for foreign keys are not the vault's guards and are left alone.
CREATE OR REPLACE FUNCTION consentvault_guard.refuse_trigger_drop() RETURNS event_trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    o record;
BEGIN
    -- forget the child records of tables this command dropped (an oid can be reused by the next table made)
    IF to_regprocedure('consentvault_guard.note_children()') IS NOT NULL THEN
        PERFORM consentvault_guard.note_children();
    END IF;
    IF consentvault_guard.break_glass() THEN
        RETURN;
    END IF;
    FOR o IN SELECT * FROM pg_catalog.pg_event_trigger_dropped_objects() LOOP
        IF o.object_type IN ('trigger', 'function') AND EXISTS (SELECT 1 FROM consentvault_guard.pin p
                                                                  WHERE p.obj OPERATOR(pg_catalog.=) o.objid
                                                                    AND p.kind OPERATOR(pg_catalog.=) o.object_type) THEN
            RAISE EXCEPTION 'consentvault trigger guard: % refused: it drops the pinned guard % % (only a superuser may)',
                tg_tag, o.object_type, o.object_identity USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF o.object_type = 'policy' AND pg_catalog.array_length(o.address_names, 1) OPERATOR(pg_catalog.>=) 3
           AND EXISTS (SELECT 1 FROM consentvault_guard.table_pin tp
                        WHERE tp.rel OPERATOR(pg_catalog.=) pg_catalog.to_regclass(
                              pg_catalog.quote_ident(o.address_names[1]) OPERATOR(pg_catalog.||) '.'
                              OPERATOR(pg_catalog.||) pg_catalog.quote_ident(o.address_names[2]))) THEN
            RAISE EXCEPTION 'consentvault trigger guard: % refused: it drops the row security policy % of a pinned guard table (only a superuser may)',
                tg_tag, o.object_identity USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF o.object_type = 'table' AND EXISTS (SELECT 1 FROM consentvault_guard.table_pin tp
                                                WHERE tp.rel OPERATOR(pg_catalog.=) o.objid) THEN
            RAISE EXCEPTION 'consentvault trigger guard: % refused: it drops the pinned guard table % and its row security (only a superuser may)',
                tg_tag, o.object_identity USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF o.object_type = 'trigger' AND o.object_identity LIKE '% on consentvault.%'
           AND o.object_identity !~ '^"?RI_ConstraintTrigger_[ac]_[0-9]+"? on ' THEN
            RAISE EXCEPTION 'consentvault trigger guard: % refused: it drops trigger % (only a superuser may)',
                tg_tag, o.object_identity USING ERRCODE = 'insufficient_privilege';
        END IF;
    END LOOP;
END;
$$;

-- Every table, in any schema, that inherits from a consentvault table (a partition or an inheritance child), directly or
-- through another child. Index partitions are not children here.
CREATE OR REPLACE FUNCTION consentvault_guard.vault_children()
    RETURNS TABLE (rel oid, parent oid, nsp oid, relname name)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH RECURSIVE d(rel, parent) AS (
        SELECT i.inhrelid, i.inhparent FROM pg_catalog.pg_inherits i
          JOIN pg_catalog.pg_class p ON p.oid OPERATOR(pg_catalog.=) i.inhparent
          JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) p.relnamespace
         WHERE n.nspname OPERATOR(pg_catalog.=) 'consentvault'
           AND p.relkind OPERATOR(pg_catalog.=) ANY (ARRAY['r', 'p', 'f']::"char"[])
        UNION
        SELECT i.inhrelid, i.inhparent FROM pg_catalog.pg_inherits i JOIN d ON i.inhparent OPERATOR(pg_catalog.=) d.rel
    )
    SELECT d.rel, d.parent, c.relnamespace, c.relname FROM d JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) d.rel
     WHERE c.relkind OPERATOR(pg_catalog.=) ANY (ARRAY['r', 'p', 'f']::"char"[]);
$$;

-- The children as they were made: parent, schema and name. Written only by note_children().
CREATE TABLE IF NOT EXISTS consentvault_guard.child (
    rel       oid NOT NULL,                 -- pg_class.oid of the child
    parent    oid NOT NULL,                 -- pg_class.oid of the table it inherits from
    nsp       oid NOT NULL,                 -- its schema when recorded
    relname   name NOT NULL,                -- its name when recorded
    noted_at  timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    noted_by  name NOT NULL DEFAULT session_user,
    PRIMARY KEY (rel, parent)
);
REVOKE ALL ON consentvault_guard.child FROM PUBLIC;
GRANT SELECT ON consentvault_guard.child TO PUBLIC;

-- Record the children. Any role (the event trigger runs as whoever ran the CREATE TABLE): forgets the records of tables
-- that no longer exist and records every child in the vault schema not yet recorded, never changing a record. A
-- superuser's run (a break-glass change) re-records every child as it stands, in any schema.
CREATE OR REPLACE FUNCTION consentvault_guard.note_children() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    n integer;
BEGIN
    DELETE FROM consentvault_guard.child c
     WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class k WHERE k.oid OPERATOR(pg_catalog.=) c.rel);
    IF consentvault_guard.session_is_break_glass() THEN
        DELETE FROM consentvault_guard.child c
         WHERE NOT EXISTS (SELECT 1 FROM consentvault_guard.vault_children() v
                            WHERE v.rel OPERATOR(pg_catalog.=) c.rel AND v.parent OPERATOR(pg_catalog.=) c.parent);
        UPDATE consentvault_guard.child c SET nsp = v.nsp, relname = v.relname
          FROM consentvault_guard.vault_children() v
         WHERE v.rel OPERATOR(pg_catalog.=) c.rel AND v.parent OPERATOR(pg_catalog.=) c.parent
           AND (v.nsp OPERATOR(pg_catalog.<>) c.nsp OR v.relname OPERATOR(pg_catalog.<>) c.relname);
        INSERT INTO consentvault_guard.child (rel, parent, nsp, relname)
        SELECT v.rel, v.parent, v.nsp, v.relname FROM consentvault_guard.vault_children() v
            ON CONFLICT (rel, parent) DO NOTHING;
    ELSE
        INSERT INTO consentvault_guard.child (rel, parent, nsp, relname)
        SELECT v.rel, v.parent, v.nsp, v.relname FROM consentvault_guard.vault_children() v
          JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) v.nsp
         WHERE n.nspname OPERATOR(pg_catalog.=) 'consentvault'
            ON CONFLICT (rel, parent) DO NOTHING;
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$;
REVOKE ALL ON FUNCTION consentvault_guard.note_children() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault_guard.note_children() TO PUBLIC;

-- After any ALTER TABLE on a consentvault table or a child of one (in any schema), every user trigger on it must still
-- fire in a normal session.
CREATE OR REPLACE FUNCTION consentvault_guard.refuse_trigger_disable() RETURNS event_trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    t record;
BEGIN
    IF consentvault_guard.break_glass() THEN
        RETURN;
    END IF;
    FOR t IN
        SELECT tg.tgname, c.oid::pg_catalog.regclass::pg_catalog.text AS tbl, tg.tgenabled
          FROM pg_catalog.pg_event_trigger_ddl_commands() d
          JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) d.objid
          JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace
          JOIN pg_catalog.pg_trigger tg ON tg.tgrelid OPERATOR(pg_catalog.=) c.oid
         WHERE d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass
           AND (n.nspname OPERATOR(pg_catalog.=) 'consentvault'
                OR c.oid OPERATOR(pg_catalog.=) ANY (ARRAY(SELECT p.rel FROM consentvault_guard.pin p
                                                           WHERE p.rel IS NOT NULL))
                OR c.oid OPERATOR(pg_catalog.=) ANY (ARRAY(SELECT v.rel FROM consentvault_guard.vault_children() v)))
           AND NOT tg.tgisinternal AND tg.tgenabled OPERATOR(pg_catalog.=) ANY (ARRAY['D', 'R']::"char"[])
    LOOP
        RAISE EXCEPTION 'consentvault trigger guard: % refused: trigger % on % would no longer fire (only a superuser may)',
            tg_tag, t.tgname, t.tbl USING ERRCODE = 'insufficient_privilege';
    END LOOP;
END;
$$;


-- The pins ---------------------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS consentvault_guard.pin (
    kind      text NOT NULL CHECK (kind IN ('function', 'trigger')),
    obj       oid NOT NULL,                 -- pg_proc.oid or pg_trigger.oid
    rel       oid,                          -- the table a trigger is on
    nsp       oid NOT NULL,                 -- the schema the function, or the trigger's table, was in when pinned
    identity  text NOT NULL,                -- consentvault.f(args) or "name on consentvault.table"
    sha256    text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    pinned_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    pinned_by name NOT NULL DEFAULT session_user,
    PRIMARY KEY (kind, obj),
    CHECK ((kind = 'trigger') = (rel IS NOT NULL))
);
REVOKE ALL ON consentvault_guard.pin FROM PUBLIC;
GRANT SELECT ON consentvault_guard.pin TO PUBLIC;

-- Row security on every guarded table and every vault table a guard function names, as a superuser pinned it.
CREATE TABLE IF NOT EXISTS consentvault_guard.table_pin (
    rel          oid PRIMARY KEY,           -- pg_class.oid
    nsp          oid NOT NULL,              -- its schema when pinned
    identity     text NOT NULL,             -- consentvault.table
    rowsec       boolean NOT NULL,          -- ENABLE ROW LEVEL SECURITY
    forcesec     boolean NOT NULL,          -- FORCE ROW LEVEL SECURITY
    policies_sha text NOT NULL CHECK (policies_sha ~ '^[0-9a-f]{64}$'),
    pinned_at    timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    pinned_by    name NOT NULL DEFAULT session_user
);
REVOKE ALL ON consentvault_guard.table_pin FROM PUBLIC;
GRANT SELECT ON consentvault_guard.table_pin TO PUBLIC;

-- The session is a superuser, or on a managed service a member of rds_superuser (the master user). Reads session_user
-- only: inside a SECURITY DEFINER function current_user is the superuser that owns it.
CREATE OR REPLACE FUNCTION consentvault_guard.session_is_break_glass() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) session_user AND r.rolsuper)
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles g WHERE g.rolname OPERATOR(pg_catalog.=) 'rds_superuser'
                    AND pg_catalog.pg_has_role(session_user, g.oid, 'MEMBER'));
$$;

CREATE OR REPLACE FUNCTION consentvault_guard.function_sha(p_fn oid) RETURNS text
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.pg_get_functiondef(p_fn), 'UTF8')), 'hex');
$$;

CREATE OR REPLACE FUNCTION consentvault_guard.trigger_sha(p_tg oid) RETURNS text
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
               pg_catalog.pg_get_triggerdef(t.oid) OPERATOR(pg_catalog.||) ' enabled=' OPERATOR(pg_catalog.||) t.tgenabled::text,
               'UTF8')), 'hex')
      FROM pg_catalog.pg_trigger t WHERE t.oid OPERATOR(pg_catalog.=) p_tg;
$$;

-- The guards as they stand: every user trigger on a vault table, its function, every vault function those call by name
-- (transitively), and the start check the API reads.
CREATE OR REPLACE FUNCTION consentvault_guard.guard_objects()
    RETURNS TABLE (kind text, obj oid, rel oid, nsp oid, identity text, sha256 text)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH RECURSIVE ns AS (
        SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.=) 'consentvault'
    ), vt AS (
        SELECT tg.oid, tg.tgname, tg.tgrelid, tg.tgfoid, c.relnamespace
          FROM pg_catalog.pg_trigger tg
          JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) tg.tgrelid
          JOIN ns ON ns.oid OPERATOR(pg_catalog.=) c.relnamespace
         WHERE NOT tg.tgisinternal
           AND tg.tgparentid OPERATOR(pg_catalog.=) 0  -- a partition's clone of its parent's trigger is the parent's guard
    ), fn(oid) AS (
        SELECT vt.tgfoid FROM vt
        UNION
        SELECT p.oid FROM pg_catalog.pg_proc p JOIN ns ON ns.oid OPERATOR(pg_catalog.=) p.pronamespace
         WHERE p.proname OPERATOR(pg_catalog.=) ANY (ARRAY['owner_rights_violations', 'require_multi_tenant']::name[])
        UNION
        SELECT q.oid FROM fn
          JOIN pg_catalog.pg_proc p ON p.oid OPERATOR(pg_catalog.=) fn.oid
          JOIN pg_catalog.pg_proc q ON q.pronamespace OPERATOR(pg_catalog.=) ANY (ARRAY(SELECT oid FROM ns))
         WHERE p.prosrc OPERATOR(pg_catalog.~) ('consentvault\.' OPERATOR(pg_catalog.||) q.proname::text
                                                OPERATOR(pg_catalog.||) '\s*\(')
    )
    SELECT 'trigger', vt.oid, vt.tgrelid, vt.relnamespace,
           vt.tgname::text OPERATOR(pg_catalog.||) ' on ' OPERATOR(pg_catalog.||) vt.tgrelid::pg_catalog.regclass::text,
           consentvault_guard.trigger_sha(vt.oid)
      FROM vt
    UNION ALL
    SELECT 'function', p.oid, NULL::oid, p.pronamespace, p.oid::pg_catalog.regprocedure::text,
           consentvault_guard.function_sha(p.oid)
      FROM fn JOIN pg_catalog.pg_proc p ON p.oid OPERATOR(pg_catalog.=) fn.oid;
$$;

-- A SHA-256 over every policy on a table: name, permissive or restrictive, command, roles, USING and WITH CHECK.
CREATE OR REPLACE FUNCTION consentvault_guard.policies_sha(p_rel oid) RETURNS text
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(coalesce(pg_catalog.string_agg(x.line, E'\n'
               ORDER BY x.line), ''), 'UTF8')), 'hex')
      FROM (SELECT p.polname::text OPERATOR(pg_catalog.||) '|' OPERATOR(pg_catalog.||) p.polpermissive::text
                   OPERATOR(pg_catalog.||) '|' OPERATOR(pg_catalog.||) p.polcmd::text
                   OPERATOR(pg_catalog.||) '|' OPERATOR(pg_catalog.||)
                   (SELECT coalesce(pg_catalog.string_agg(n.r, ',' ORDER BY n.r), '')
                      FROM (SELECT CASE WHEN o OPERATOR(pg_catalog.=) 0 THEN 'public'
                                        ELSE pg_catalog.pg_get_userbyid(o)::text END AS r
                              FROM pg_catalog.unnest(p.polroles) o) n)
                   OPERATOR(pg_catalog.||) '|' OPERATOR(pg_catalog.||) coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), '')
                   OPERATOR(pg_catalog.||) '|' OPERATOR(pg_catalog.||) coalesce(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
                   AS line
              FROM pg_catalog.pg_policy p WHERE p.polrelid OPERATOR(pg_catalog.=) p_rel) x;
$$;

-- The tables whose row security the guards depend on: every vault table a guard trigger is on, and every vault table a
-- guard function names (consentvault.<table> in its body).
CREATE OR REPLACE FUNCTION consentvault_guard.guard_tables()
    RETURNS TABLE (rel oid, nsp oid, identity text, rowsec boolean, forcesec boolean, policies_sha text)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH g AS (SELECT * FROM consentvault_guard.guard_objects()
    ), ns AS (
        SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.=) 'consentvault'
    ), rels AS (
        SELECT g.rel AS oid FROM g WHERE g.kind OPERATOR(pg_catalog.=) 'trigger'
        UNION
        SELECT c.oid FROM g
          JOIN pg_catalog.pg_proc p ON p.oid OPERATOR(pg_catalog.=) g.obj
          CROSS JOIN LATERAL pg_catalog.regexp_matches(p.prosrc, 'consentvault\.([a-z_][a-z0-9_]*)', 'g') m
          JOIN pg_catalog.pg_class c ON c.relname OPERATOR(pg_catalog.=) m[1]::name
                                     AND c.relnamespace OPERATOR(pg_catalog.=) ANY (ARRAY(SELECT oid FROM ns))
         WHERE g.kind OPERATOR(pg_catalog.=) 'function' AND c.relkind OPERATOR(pg_catalog.=) ANY (ARRAY['r', 'p']::"char"[])
    )
    SELECT c.oid, c.relnamespace, c.oid::pg_catalog.regclass::text, c.relrowsecurity, c.relforcerowsecurity,
           consentvault_guard.policies_sha(c.oid)
      FROM rels JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) rels.oid;
$$;

-- Pin every guard and guard table not yet pinned. A superuser's only: the schema owner cannot pin what it just added.
-- Insert-only: a pinned guard that changed stays a violation until a superuser reviews it and runs repin().
CREATE OR REPLACE FUNCTION consentvault_guard.pin_guards() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    n integer;
    t integer;
BEGIN
    IF NOT consentvault_guard.session_is_break_glass() THEN
        RAISE EXCEPTION 'consentvault trigger guard: pinning the guards refused for %: only a superuser may', session_user
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    INSERT INTO consentvault_guard.pin (kind, obj, rel, nsp, identity, sha256)
    SELECT g.kind, g.obj, g.rel, g.nsp, g.identity, g.sha256 FROM consentvault_guard.guard_objects() g
        ON CONFLICT (kind, obj) DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    INSERT INTO consentvault_guard.table_pin (rel, nsp, identity, rowsec, forcesec, policies_sha)
    SELECT g.rel, g.nsp, g.identity, g.rowsec, g.forcesec, g.policies_sha FROM consentvault_guard.guard_tables() g
        ON CONFLICT (rel) DO NOTHING;
    GET DIAGNOSTICS t = ROW_COUNT;
    RETURN n + t;
END;
$$;
REVOKE ALL ON FUNCTION consentvault_guard.pin_guards() FROM PUBLIC;

-- Re-pin every guard as it stands now, after a reviewed break-glass change. A superuser's only.
CREATE OR REPLACE FUNCTION consentvault_guard.repin() RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) session_user AND r.rolsuper)
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles g WHERE g.rolname OPERATOR(pg_catalog.=) 'rds_superuser'
                        AND pg_catalog.pg_has_role(session_user, g.oid, 'MEMBER')) THEN
        RAISE EXCEPTION 'consentvault trigger guard: re-pinning the guards refused for %: only a superuser may', session_user
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    DELETE FROM consentvault_guard.pin;
    DELETE FROM consentvault_guard.table_pin;
    RETURN consentvault_guard.pin_guards();
END;
$$;
REVOKE ALL ON FUNCTION consentvault_guard.repin() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault_guard.repin() TO PUBLIC;

-- Every pinned guard that changed or is gone, and every guard not pinned. The API refuses to start on any row.
CREATE OR REPLACE FUNCTION consentvault_guard.pin_violations()
    RETURNS TABLE (object_kind text, object_name text, owner_name text, problem text)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH cur AS (
        SELECT p.kind, p.identity, p.sha256 AS pinned, p.nsp AS pinned_nsp,
               CASE p.kind WHEN 'function' THEN consentvault_guard.function_sha(f.oid)
                           ELSE consentvault_guard.trigger_sha(t.oid) END AS now_sha,
               CASE p.kind WHEN 'function' THEN f.oid::pg_catalog.regprocedure::text
                           ELSE t.tgname::text OPERATOR(pg_catalog.||) ' on '
                                OPERATOR(pg_catalog.||) t.tgrelid::pg_catalog.regclass::text END AS now_identity,
               coalesce(f.pronamespace, c.relnamespace) AS now_nsp,
               coalesce(pg_catalog.pg_get_userbyid(coalesce(f.proowner, c.relowner)), '-') AS owner_name
          FROM consentvault_guard.pin p
          LEFT JOIN pg_catalog.pg_proc f ON p.kind OPERATOR(pg_catalog.=) 'function' AND f.oid OPERATOR(pg_catalog.=) p.obj
          LEFT JOIN pg_catalog.pg_trigger t ON p.kind OPERATOR(pg_catalog.=) 'trigger' AND t.oid OPERATOR(pg_catalog.=) p.obj
          LEFT JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) t.tgrelid
    )
    SELECT cur.kind, cur.identity, cur.owner_name,
           CASE WHEN cur.now_sha IS NULL
                THEN 'a pinned guard ' OPERATOR(pg_catalog.||) cur.kind OPERATOR(pg_catalog.||) ' is gone'
                ELSE 'a pinned guard ' OPERATOR(pg_catalog.||) cur.kind OPERATOR(pg_catalog.||) ' changed' END
           OPERATOR(pg_catalog.||) ': pinned sha256 ' OPERATOR(pg_catalog.||) cur.pinned
           OPERATOR(pg_catalog.||) ' as ' OPERATOR(pg_catalog.||) cur.identity
           OPERATOR(pg_catalog.||) ', now ' OPERATOR(pg_catalog.||) coalesce(cur.now_sha, 'absent')
           OPERATOR(pg_catalog.||) ' as ' OPERATOR(pg_catalog.||) coalesce(cur.now_identity, 'absent')
           OPERATOR(pg_catalog.||) ' (a superuser reviews the change and runs SELECT consentvault_guard.repin())'
      FROM cur
     WHERE cur.now_sha IS NULL OR cur.now_sha OPERATOR(pg_catalog.<>) cur.pinned
        OR cur.now_identity OPERATOR(pg_catalog.<>) cur.identity OR cur.now_nsp OPERATOR(pg_catalog.<>) cur.pinned_nsp
    UNION ALL
    SELECT g.kind, g.identity, '-',
           'a guard ' OPERATOR(pg_catalog.||) g.kind OPERATOR(pg_catalog.||) ' is not pinned: the migration that made it '
           'runs SELECT consentvault_guard.pin_guards()'
      FROM consentvault_guard.guard_objects() g
     WHERE NOT EXISTS (SELECT 1 FROM consentvault_guard.pin p
                        WHERE p.kind OPERATOR(pg_catalog.=) g.kind AND p.obj OPERATOR(pg_catalog.=) g.obj)
    UNION ALL
    SELECT 'table', tp.identity, coalesce(pg_catalog.pg_get_userbyid(c.relowner), '-'),
           CASE WHEN c.oid IS NULL THEN 'a pinned guard table is gone' ELSE 'a pinned guard table changed' END
           OPERATOR(pg_catalog.||) ': pinned row security ' OPERATOR(pg_catalog.||) tp.rowsec::text
           OPERATOR(pg_catalog.||) ', force ' OPERATOR(pg_catalog.||) tp.forcesec::text
           OPERATOR(pg_catalog.||) ', policies sha256 ' OPERATOR(pg_catalog.||) tp.policies_sha
           OPERATOR(pg_catalog.||) ' as ' OPERATOR(pg_catalog.||) tp.identity
           OPERATOR(pg_catalog.||) '; now ' OPERATOR(pg_catalog.||) coalesce(c.relrowsecurity::text, 'absent')
           OPERATOR(pg_catalog.||) ', force ' OPERATOR(pg_catalog.||) coalesce(c.relforcerowsecurity::text, 'absent')
           OPERATOR(pg_catalog.||) ', policies sha256 '
           OPERATOR(pg_catalog.||) coalesce(consentvault_guard.policies_sha(c.oid), 'absent')
           OPERATOR(pg_catalog.||) ' as ' OPERATOR(pg_catalog.||) coalesce(c.oid::pg_catalog.regclass::text, 'absent')
           OPERATOR(pg_catalog.||) ' (a superuser reviews the change and runs SELECT consentvault_guard.repin())'
      FROM consentvault_guard.table_pin tp
      LEFT JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) tp.rel
     WHERE c.oid IS NULL OR c.relrowsecurity IS DISTINCT FROM tp.rowsec OR c.relforcerowsecurity IS DISTINCT FROM tp.forcesec
        OR consentvault_guard.policies_sha(c.oid) OPERATOR(pg_catalog.<>) tp.policies_sha
        OR c.oid::pg_catalog.regclass::text OPERATOR(pg_catalog.<>) tp.identity
        OR c.relnamespace OPERATOR(pg_catalog.<>) tp.nsp
    UNION ALL
    SELECT 'table', g.identity, '-',
           'a guard table is not pinned: a superuser runs SELECT consentvault_guard.pin_guards() after the migration run'
      FROM consentvault_guard.guard_tables() g
     WHERE NOT EXISTS (SELECT 1 FROM consentvault_guard.table_pin tp WHERE tp.rel OPERATOR(pg_catalog.=) g.rel)
    UNION ALL
    SELECT 'function', 'consentvault_guard.pin_guards()', pg_catalog.pg_get_userbyid(p.proowner),
           'pinning the guards can be run by a role that is not a superuser ('
           OPERATOR(pg_catalog.||) (SELECT pg_catalog.string_agg(r.rolname::text, ', ' ORDER BY r.rolname)
                                      FROM pg_catalog.pg_roles r
                                     WHERE NOT r.rolsuper
                                       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles g
                                                        WHERE g.rolname OPERATOR(pg_catalog.=) 'rds_superuser'
                                                          AND pg_catalog.pg_has_role(r.oid, g.oid, 'MEMBER'))
                                       AND pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE'))
           OPERATOR(pg_catalog.||) '): run docker/initdb/20-trigger-guard.sql again as a superuser'
      FROM pg_catalog.pg_proc p
     WHERE p.oid OPERATOR(pg_catalog.=) 'consentvault_guard.pin_guards()'::pg_catalog.regprocedure
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                    WHERE NOT r.rolsuper
                      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles g
                                       WHERE g.rolname OPERATOR(pg_catalog.=) 'rds_superuser'
                                         AND pg_catalog.pg_has_role(r.oid, g.oid, 'MEMBER'))
                      AND pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE'));
$$;

-- Refuse, for every role but a superuser, a change to a pinned guard and the renames that hide one from the guard. A
-- statement that leaves a pinned guard byte for byte as pinned (re-running the migration that made it) is no change.
CREATE OR REPLACE FUNCTION consentvault_guard.refuse_guard_change() RETURNS event_trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    d record;
    what text;
BEGIN
    IF consentvault_guard.break_glass() THEN
        RETURN;
    END IF;
    FOR d IN SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands() LOOP
        what := NULL;
        -- a replacement that leaves a pinned guard exactly as pinned (same definition, same name) changes nothing
        IF d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass
           AND EXISTS (SELECT 1 FROM consentvault_guard.pin p WHERE p.kind OPERATOR(pg_catalog.=) 'function'
                        AND p.obj OPERATOR(pg_catalog.=) d.objid
                        AND (consentvault_guard.function_sha(d.objid) IS DISTINCT FROM p.sha256
                             OR d.objid::pg_catalog.regprocedure::text IS DISTINCT FROM p.identity)) THEN
            what := 'it changes the pinned guard function ' OPERATOR(pg_catalog.||) d.object_identity;
        ELSIF d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_trigger'::pg_catalog.regclass
              AND EXISTS (SELECT 1 FROM consentvault_guard.pin p, pg_catalog.pg_trigger t
                           WHERE t.oid OPERATOR(pg_catalog.=) d.objid AND p.kind OPERATOR(pg_catalog.=) 'trigger'
                             AND (p.obj OPERATOR(pg_catalog.=) t.oid
                                  OR (p.rel OPERATOR(pg_catalog.=) t.tgrelid
                                      AND p.identity OPERATOR(pg_catalog.=) (t.tgname::text OPERATOR(pg_catalog.||) ' on '
                                          OPERATOR(pg_catalog.||) t.tgrelid::pg_catalog.regclass::text)))
                             AND (consentvault_guard.trigger_sha(t.oid) IS DISTINCT FROM p.sha256
                                  OR p.obj OPERATOR(pg_catalog.<>) t.oid
                                  OR p.identity IS DISTINCT FROM (t.tgname::text OPERATOR(pg_catalog.||) ' on '
                                          OPERATOR(pg_catalog.||) t.tgrelid::pg_catalog.regclass::text))) THEN
            what := 'it replaces or renames the pinned guard trigger ' OPERATOR(pg_catalog.||) d.object_identity;
        ELSIF d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_namespace'::pg_catalog.regclass
              AND (d.object_identity OPERATOR(pg_catalog.=) ANY (ARRAY['consentvault', 'consentvault_guard'])
                   OR EXISTS (SELECT 1 FROM consentvault_guard.pin p WHERE p.nsp OPERATOR(pg_catalog.=) d.objid)) THEN
            what := 'it alters the vault schema (now named ' OPERATOR(pg_catalog.||) d.object_identity OPERATOR(pg_catalog.||) ')';
        ELSIF d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass
              AND EXISTS (SELECT 1 FROM consentvault_guard.pin p
                            JOIN pg_catalog.pg_trigger t ON t.oid OPERATOR(pg_catalog.=) p.obj
                            JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) p.rel
                           WHERE p.rel OPERATOR(pg_catalog.=) d.objid
                             AND (c.relnamespace OPERATOR(pg_catalog.<>) p.nsp
                                  OR p.identity OPERATOR(pg_catalog.<>) (t.tgname::text OPERATOR(pg_catalog.||) ' on '
                                     OPERATOR(pg_catalog.||) t.tgrelid::pg_catalog.regclass::text))) THEN
            what := 'the guarded table ' OPERATOR(pg_catalog.||) d.object_identity
                    OPERATOR(pg_catalog.||) ' leaves its schema or its name';
        ELSIF d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass
              AND EXISTS (SELECT 1 FROM consentvault_guard.vault_children() v
                            JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) v.nsp
                           WHERE v.rel OPERATOR(pg_catalog.=) d.objid
                             AND n.nspname OPERATOR(pg_catalog.<>) 'consentvault') THEN
            what := 'the table ' OPERATOR(pg_catalog.||) d.object_identity
                    OPERATOR(pg_catalog.||) ', a child of a vault table, leaves the vault schema';
        END IF;
        IF what IS NOT NULL THEN
            RAISE EXCEPTION 'consentvault trigger guard: % refused: % (only a superuser may)', d.command_tag, what
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END LOOP;
END;
$$;

-- Refuse, for every role but a superuser, a policy created or altered on a pinned guard table, and an ALTER TABLE that
-- leaves a pinned guard table's row security flags other than pinned (ENABLE / DISABLE / FORCE / NO FORCE ROW LEVEL
-- SECURITY). A dropped policy is refused by refuse_trigger_drop (sql_drop).
CREATE OR REPLACE FUNCTION consentvault_guard.refuse_policy_change() RETURNS event_trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    d record;
    t text;
BEGIN
    IF consentvault_guard.break_glass() THEN
        RETURN;
    END IF;
    FOR d IN SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands() LOOP
        t := NULL;
        IF d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_policy'::pg_catalog.regclass THEN
            SELECT tp.identity INTO t FROM pg_catalog.pg_policy p
              JOIN consentvault_guard.table_pin tp ON tp.rel OPERATOR(pg_catalog.=) p.polrelid
             WHERE p.oid OPERATOR(pg_catalog.=) d.objid;
            IF t IS NOT NULL THEN
                RAISE EXCEPTION 'consentvault trigger guard: % refused: it changes a row security policy of the pinned guard table % (only a superuser may)',
                    d.command_tag, t USING ERRCODE = 'insufficient_privilege';
            END IF;
        ELSIF d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass THEN
            SELECT tp.identity INTO t FROM consentvault_guard.table_pin tp
              JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) tp.rel
             WHERE tp.rel OPERATOR(pg_catalog.=) d.objid
               AND (c.relrowsecurity IS DISTINCT FROM tp.rowsec OR c.relforcerowsecurity IS DISTINCT FROM tp.forcesec);
            IF t IS NOT NULL THEN
                RAISE EXCEPTION 'consentvault trigger guard: % refused: it switches row security on the pinned guard table % (only a superuser may)',
                    d.command_tag, t USING ERRCODE = 'insufficient_privilege';
            END IF;
        END IF;
    END LOOP;
END;
$$;

-- Refuse, for every role but a superuser, a change to a vault table's children: a child made or moved outside the vault
-- schema, a recorded child renamed, moved, detached or un-inherited, and a table attached to a vault table by ALTER
-- TABLE (INHERIT, ATTACH PARTITION). A vault table's children are made by CREATE TABLE ... PARTITION OF (or INHERITS) in
-- the vault schema, and recorded then. A superuser's change is re-recorded as it stands.
CREATE OR REPLACE FUNCTION consentvault_guard.refuse_vault_child_change() RETURNS event_trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    d record;
    v record;
    r record;
BEGIN
    IF consentvault_guard.break_glass() THEN
        PERFORM consentvault_guard.note_children();
        RETURN;
    END IF;
    FOR d IN SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands() x
              WHERE x.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass LOOP
        FOR v IN SELECT x.rel, x.parent,
                        EXISTS (SELECT 1 FROM consentvault_guard.child c WHERE c.rel OPERATOR(pg_catalog.=) x.rel
                                   AND c.parent OPERATOR(pg_catalog.=) x.parent) AS recorded
                   FROM consentvault_guard.vault_children() x
                   JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) x.nsp
                  WHERE x.rel OPERATOR(pg_catalog.=) d.objid AND n.nspname OPERATOR(pg_catalog.<>) 'consentvault' LOOP
            IF v.recorded THEN
                RAISE EXCEPTION 'consentvault trigger guard: % refused: the table %, a child of the vault table %, leaves the vault schema (only a superuser may)',
                    tg_tag, v.rel::pg_catalog.regclass, v.parent::pg_catalog.regclass USING ERRCODE = 'insufficient_privilege';
            END IF;
            RAISE EXCEPTION 'consentvault trigger guard: % refused: the table % is a child of the vault table % made outside the vault schema (only a superuser may)',
                tg_tag, v.rel::pg_catalog.regclass, v.parent::pg_catalog.regclass USING ERRCODE = 'insufficient_privilege';
        END LOOP;
    END LOOP;
    FOR r IN SELECT c.rel, c.parent, c.relname, k.relname AS now_name, c.nsp, k.relnamespace AS now_nsp,
                    pg_catalog.quote_ident(coalesce(n.nspname, '?')) OPERATOR(pg_catalog.||) '.'
                    OPERATOR(pg_catalog.||) pg_catalog.quote_ident(c.relname) AS was,
                    EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid OPERATOR(pg_catalog.=) c.rel
                               AND i.inhparent OPERATOR(pg_catalog.=) c.parent) AS still_child
               FROM consentvault_guard.child c
               JOIN pg_catalog.pg_class k ON k.oid OPERATOR(pg_catalog.=) c.rel
               LEFT JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.nsp LOOP
        IF NOT r.still_child THEN
            RAISE EXCEPTION 'consentvault trigger guard: % refused: it detaches % from the vault table % (only a superuser may)',
                tg_tag, r.was, r.parent::pg_catalog.regclass USING ERRCODE = 'insufficient_privilege';
        END IF;
        IF r.now_name OPERATOR(pg_catalog.<>) r.relname OR r.now_nsp OPERATOR(pg_catalog.<>) r.nsp THEN
            RAISE EXCEPTION 'consentvault trigger guard: % refused: it renames or moves %, a child of the vault table %, to % (only a superuser may)',
                tg_tag, r.was, r.parent::pg_catalog.regclass, r.rel::pg_catalog.regclass USING ERRCODE = 'insufficient_privilege';
        END IF;
    END LOOP;
    IF tg_tag OPERATOR(pg_catalog.=) ANY (ARRAY['CREATE TABLE', 'CREATE FOREIGN TABLE']) THEN
        PERFORM consentvault_guard.note_children();
        RETURN;
    END IF;
    FOR v IN SELECT x.rel, x.parent FROM consentvault_guard.vault_children() x
              WHERE NOT EXISTS (SELECT 1 FROM consentvault_guard.child c WHERE c.rel OPERATOR(pg_catalog.=) x.rel
                                   AND c.parent OPERATOR(pg_catalog.=) x.parent) LOOP
        RAISE EXCEPTION 'consentvault trigger guard: % refused: it attaches % to the vault table % (a vault table''s children are made by CREATE TABLE in the vault schema; only a superuser may)',
            tg_tag, v.rel::pg_catalog.regclass, v.parent::pg_catalog.regclass USING ERRCODE = 'insufficient_privilege';
    END LOOP;
END;
$$;

-- Record the children that exist now (a superuser runs this file, so every child is recorded as it stands).
SELECT consentvault_guard.note_children();

DROP EVENT TRIGGER IF EXISTS consentvault_refuse_trigger_drop;
CREATE EVENT TRIGGER consentvault_refuse_trigger_drop ON sql_drop
    EXECUTE FUNCTION consentvault_guard.refuse_trigger_drop();
DROP EVENT TRIGGER IF EXISTS consentvault_refuse_trigger_disable;
CREATE EVENT TRIGGER consentvault_refuse_trigger_disable ON ddl_command_end WHEN TAG IN ('ALTER TABLE')
    EXECUTE FUNCTION consentvault_guard.refuse_trigger_disable();
DROP EVENT TRIGGER IF EXISTS consentvault_refuse_guard_change;
CREATE EVENT TRIGGER consentvault_refuse_guard_change ON ddl_command_end
    WHEN TAG IN ('CREATE FUNCTION', 'ALTER FUNCTION', 'ALTER ROUTINE', 'CREATE TRIGGER', 'ALTER TRIGGER', 'ALTER SCHEMA',
                 'ALTER TABLE')
    EXECUTE FUNCTION consentvault_guard.refuse_guard_change();
DROP EVENT TRIGGER IF EXISTS consentvault_refuse_policy_change;
CREATE EVENT TRIGGER consentvault_refuse_policy_change ON ddl_command_end
    WHEN TAG IN ('CREATE POLICY', 'ALTER POLICY', 'ALTER TABLE')
    EXECUTE FUNCTION consentvault_guard.refuse_policy_change();
DROP EVENT TRIGGER IF EXISTS consentvault_refuse_vault_child_change;
CREATE EVENT TRIGGER consentvault_refuse_vault_child_change ON ddl_command_end
    WHEN TAG IN ('CREATE TABLE', 'ALTER TABLE', 'CREATE FOREIGN TABLE', 'ALTER FOREIGN TABLE')
    EXECUTE FUNCTION consentvault_guard.refuse_vault_child_change();
