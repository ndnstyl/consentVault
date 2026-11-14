-- The two scheduled self-checks that need a place in the database: the nightly isolation self-test and the restore drill.
-- Each runs as its own group role through a dedicated login (the pattern of the integrity jobs, 0048, and the records
-- jobs, 0050). The roles are made once per cluster by a superuser (docker/initdb/10-roles.sh, or the managed database's
-- master user); this migration refuses to run without them.
--
-- consentvault_isolation_self_test may, and nothing more:
--   * take the canary pair (isolation_canary_pair: two closed organisations made on the first call and kept, each with an
--     organisation row, a brand and a capture source) and a two-minute token for a canary only (isolation_canary_token),
--     never for a real organisation; enter it (enter_org, current_org, current_token_scopes);
--   * SELECT every tenant table and view (every org_id table but the two platform tables), so that under a canary's token it
--     reads exactly what row security lets through, and run the functions the row-security policies call.
--   It holds no INSERT, UPDATE, DELETE or TRUNCATE anywhere, no token signing and no dispatch. A table a later migration adds
--   with an org_id column is granted to this group by the migration runner (isolation_self_test_grant_reads, below); one
--   the group still cannot read is a finding every night (tests/isolation/test_isolation_self_test.py names it too).
--
-- consentvault_restore_drill may, and nothing more: append one drill record (record_restore_drill) and read the records
-- (restore_drill_runs). The drill itself runs against a scratch copy, never this database.
--
-- The operator console reads the drill records too (restore_drill_runs).

DO $$
DECLARE
    g text;
BEGIN
    FOREACH g IN ARRAY ARRAY['consentvault_isolation_self_test', 'consentvault_restore_drill'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = g) THEN
            RAISE EXCEPTION 'consentvault migration 0059 refused: the role % does not exist. As a superuser (or the managed '
                            'database master user) run: CREATE ROLE % NOLOGIN; then create its login as a member of it '
                            '(docs/deployment.md, "Roles")', g, g
                USING ERRCODE = 'undefined_object';
        END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = g AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
            RAISE EXCEPTION 'consentvault migration 0059 refused: % must be a NOLOGIN group, neither a superuser nor BYPASSRLS', g
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END LOOP;
END
$$;

-- ---- the isolation canary pair -----------------------------------------------------------------------------------------------
-- Owner-only, no org_id: which organisations are the canaries. Written once per label, never changed.
CREATE TABLE consentvault.isolation_canary (
    label      text PRIMARY KEY CHECK (label IN ('a', 'b')),
    canary_org uuid NOT NULL UNIQUE REFERENCES consentvault.organization (org_id),
    created_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON consentvault.isolation_canary FROM PUBLIC;

CREATE FUNCTION consentvault.isolation_canary_frozen() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'consentvault isolation canary: a canary is written once and never changed or removed'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;
CREATE TRIGGER isolation_canary_frozen BEFORE UPDATE OR DELETE ON consentvault.isolation_canary
    FOR EACH ROW EXECUTE FUNCTION consentvault.isolation_canary_frozen();
CREATE TRIGGER isolation_canary_no_truncate BEFORE TRUNCATE ON consentvault.isolation_canary
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.isolation_canary_frozen();

-- The pair, made on the first call: each canary is a closed organisation (no sign-in, no capture, outside every evidence
-- and billing job), written inside its own tenant under a one-minute token, as the admin path creates an organisation.
CREATE FUNCTION consentvault.isolation_canary_pair() RETURNS TABLE (label text, org_id uuid)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    l      text;
    o      uuid;
    b      uuid;
    prior  text := pg_catalog.current_setting('consentvault.org_token', true);
BEGIN
    IF (SELECT s.mode FROM consentvault.tenancy_setting s WHERE s.singleton) IS DISTINCT FROM 'multi' THEN
        RAISE EXCEPTION 'consentvault isolation self-test: the vault is in single-company mode; there is nothing to isolate'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('consentvault.isolation_canary'));
    FOREACH l IN ARRAY ARRAY['a', 'b'] LOOP
        IF NOT EXISTS (SELECT 1 FROM consentvault.isolation_canary c WHERE c.label = l) THEN
            o := gen_random_uuid();
            PERFORM pg_catalog.set_config('consentvault.org_token',
                                          consentvault.sign_org_token(o, ARRAY['admin'], NULL, 60), true);
            PERFORM pg_catalog.set_config('consentvault.status_actor', 'isolation-self-test', true);
            INSERT INTO consentvault.organization (org_id, name, status) VALUES (o, 'isolation canary ' || l, 'closed');
            INSERT INTO consentvault.brand (org_id, display_name) VALUES (o, 'isolation canary ' || l)
                RETURNING brand_id INTO b;
            INSERT INTO consentvault.capture_source (org_id, kind, brand_ids, allowed_origins)
                VALUES (o, 'form', ARRAY[b], ARRAY['https://canary-' || l || '.invalid']);
            INSERT INTO consentvault.isolation_canary (label, canary_org) VALUES (l, o);
        END IF;
    END LOOP;
    PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prior, ''), true);
    RETURN QUERY SELECT c.label, c.canary_org FROM consentvault.isolation_canary c ORDER BY c.label;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.isolation_canary_pair() FROM PUBLIC;

-- A two-minute token for one canary, with every read scope a row-security policy admits, so the probe reads what any
-- reader could. Refused by name for anything but the two labels: no real organisation's token is ever handed out here.
CREATE FUNCTION consentvault.isolation_canary_token(p_label text) RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    o uuid;
BEGIN
    SELECT c.canary_org INTO o FROM consentvault.isolation_canary c WHERE c.label = p_label;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault isolation self-test: there is no canary %; only a and b exist, made by isolation_canary_pair()',
            p_label USING ERRCODE = 'no_data_found';
    END IF;
    RETURN consentvault.sign_org_token(o, ARRAY['admin', 'audit_read', 'developer', 'gate_read', 'proof_read', 'records_read',
                                                'worker:display_key'], NULL, 120);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.isolation_canary_token(text) FROM PUBLIC;

GRANT USAGE ON SCHEMA consentvault TO consentvault_isolation_self_test;
GRANT EXECUTE ON FUNCTION consentvault.isolation_canary_pair(), consentvault.isolation_canary_token(text),
    consentvault.enter_org(text), consentvault.current_org(), consentvault.current_token_scopes()
    TO consentvault_isolation_self_test;

-- SELECT on every tenant table that forces row security and every tenant view that runs with its reader's rights
-- (security_invoker), and EXECUTE on the exact functions a row-security policy depends on that run with the caller's
-- rights (a policy runs with the reader's rights, so a probe without them would fail on the policy, not on the data).
-- Never a table without forced row security, never a view that runs with its owner's rights, never an owner-rights
-- (SECURITY DEFINER) function: those would read past row security. The migration runner calls this after every
-- migration, inside that migration's transaction (src/consentvault/db.py), so a table a later migration adds is covered
-- the moment it exists, and a clean apply and a live database hold the same grants.
CREATE FUNCTION consentvault.isolation_self_test_grant_reads() RETURNS void
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT c.oid::regclass AS rel FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attname = 'org_id' AND NOT a.attisdropped
             WHERE n.nspname = 'consentvault' AND NOT c.relispartition
               AND c.relname NOT IN ('replay_guard', 'billing_event')
               AND ((c.relkind IN ('r', 'p') AND c.relrowsecurity AND c.relforcerowsecurity)
                    OR (c.relkind = 'v' AND 'security_invoker=true' = ANY (coalesce(c.reloptions, ARRAY[]::text[]))))
               AND NOT pg_catalog.has_table_privilege('consentvault_isolation_self_test', c.oid, 'SELECT') LOOP
        EXECUTE pg_catalog.format('GRANT SELECT ON %s TO consentvault_isolation_self_test', r.rel);
    END LOOP;
    FOR r IN SELECT DISTINCT p.oid::regprocedure AS fn FROM pg_catalog.pg_depend d
              JOIN pg_catalog.pg_policy pol ON d.classid = 'pg_catalog.pg_policy'::regclass AND d.objid = pol.oid
              JOIN pg_catalog.pg_class pc ON pc.oid = pol.polrelid
              JOIN pg_catalog.pg_namespace pcn ON pcn.oid = pc.relnamespace AND pcn.nspname = 'consentvault'
              JOIN pg_catalog.pg_proc p ON d.refclassid = 'pg_catalog.pg_proc'::regclass AND d.refobjid = p.oid
             WHERE NOT p.prosecdef
               AND NOT pg_catalog.has_function_privilege('consentvault_isolation_self_test', p.oid, 'EXECUTE') LOOP
        EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION %s TO consentvault_isolation_self_test', r.fn);
    END LOOP;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.isolation_self_test_grant_reads() FROM PUBLIC;
SELECT consentvault.isolation_self_test_grant_reads();
-- The two owner-rights functions the policies call, granted by name after review: current_org() (above) and the legal
-- hold's disclosure check, which answers a yes or no about one hold and reads nothing else.
GRANT EXECUTE ON FUNCTION consentvault.legal_process_disclosed(uuid, uuid) TO consentvault_isolation_self_test;

-- ---- the restore drill record --------------------------------------------------------------------------------------------------
-- Owner-only, append-only: one row per drill (when, which backup, how long against the stated target, the outcome, and the
-- report: counts, organisation ids and check names, never a row of a tenant).
CREATE TABLE consentvault.restore_drill_run (
    drill_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    recorded_at     timestamptz NOT NULL DEFAULT now(),
    recorded_by     text NOT NULL DEFAULT current_user,
    backup_ref      text NOT NULL CHECK (length(backup_ref) BETWEEN 1 AND 256),
    backup_taken_at timestamptz NOT NULL,
    started_at      timestamptz NOT NULL,
    finished_at     timestamptz NOT NULL CHECK (finished_at >= started_at),
    seconds         numeric NOT NULL CHECK (seconds >= 0),
    target_seconds  integer NOT NULL CHECK (target_seconds > 0),
    outcome         text NOT NULL CHECK (outcome IN ('passed', 'failed')),
    orgs            integer NOT NULL CHECK (orgs >= 0),
    report          jsonb NOT NULL CHECK (jsonb_typeof(report) = 'object' AND length(report::text) <= 200000)
);
REVOKE ALL ON consentvault.restore_drill_run FROM PUBLIC;

CREATE FUNCTION consentvault.restore_drill_run_frozen() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'consentvault restore drill: a drill record is written once and never changed or removed'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;
CREATE TRIGGER restore_drill_run_frozen BEFORE UPDATE OR DELETE ON consentvault.restore_drill_run
    FOR EACH ROW EXECUTE FUNCTION consentvault.restore_drill_run_frozen();
CREATE TRIGGER restore_drill_run_no_truncate BEFORE TRUNCATE ON consentvault.restore_drill_run
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.restore_drill_run_frozen();

CREATE FUNCTION consentvault.record_restore_drill(p_backup_ref text, p_backup_taken_at timestamptz, p_started_at timestamptz,
                                                  p_finished_at timestamptz, p_target_seconds integer, p_outcome text,
                                                  p_orgs integer, p_report jsonb) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    id uuid;
BEGIN
    INSERT INTO consentvault.restore_drill_run (recorded_by, backup_ref, backup_taken_at, started_at, finished_at, seconds,
                                                target_seconds, outcome, orgs, report)
        VALUES (session_user, p_backup_ref, p_backup_taken_at, p_started_at, p_finished_at,
                extract(epoch FROM p_finished_at - p_started_at), p_target_seconds, p_outcome, p_orgs, p_report)
        RETURNING drill_id INTO id;
    RETURN id;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_restore_drill(text, timestamptz, timestamptz, timestamptz, integer, text, integer, jsonb)
    FROM PUBLIC;

CREATE FUNCTION consentvault.restore_drill_runs(p_limit integer) RETURNS SETOF consentvault.restore_drill_run
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT * FROM consentvault.restore_drill_run ORDER BY recorded_at DESC, drill_id LIMIT least(greatest(p_limit, 1), 1000);
$$;
REVOKE ALL ON FUNCTION consentvault.restore_drill_runs(integer) FROM PUBLIC;

GRANT USAGE ON SCHEMA consentvault TO consentvault_restore_drill;
GRANT EXECUTE ON FUNCTION consentvault.record_restore_drill(text, timestamptz, timestamptz, timestamptz, integer, text, integer, jsonb),
    consentvault.restore_drill_runs(integer) TO consentvault_restore_drill;
GRANT EXECUTE ON FUNCTION consentvault.restore_drill_runs(integer) TO consentvault_console;
