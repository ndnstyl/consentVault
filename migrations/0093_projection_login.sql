-- The projection runs under a role that cannot read the organisation's configuration (one-door review round 9). Rounds 5 to 9 each
-- found a decision made during projection from live configuration instead of the facts stored at arrival, and a scan of the source
-- can always be evaded, so the guard is made structural: the projection switches to consentvault_projection (SET ROLE, from the
-- app login, which is a member of it) for everything it does, and that role holds everything consentvault_app holds EXCEPT any
-- read of the configuration tables below. A planted read of one of them, however it is written, raises "permission denied".
--
-- Not readable by the projection: capture_source (source status, brands, origins), brand, disclosure (a grant's wording is read
-- from the fact stored at arrival; the ledger's own grant-scope check is a security-definer trigger and still sees it), channel and
-- purpose (the lists), credential (site keys), retention_policy (read at intake and stored), tenancy_setting, and organization except its id and status (the region, the
-- default settings). Everything else is the app's, copied at the time this runs and again whenever sync_projection_grants() is
-- called, which every later migration that grants the app something must do (tests/test_projection_login.py names any drift).
--
-- The role is made once per cluster by a superuser (docker/initdb/10-roles.sh, or the managed database's master user) and the
-- app group is made a member of it there: CREATE ROLE consentvault_projection NOLOGIN; GRANT consentvault_projection TO
-- consentvault_app. This migration refuses to run without them.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_projection') THEN
        RAISE EXCEPTION 'consentvault migration 0093 refused: the role consentvault_projection does not exist. As a superuser '
                        '(or the managed database master user) run: CREATE ROLE consentvault_projection NOLOGIN; '
                        'GRANT consentvault_projection TO consentvault_app'
            USING ERRCODE = 'undefined_object';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_projection' AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
        RAISE EXCEPTION 'consentvault migration 0093 refused: consentvault_projection must be a NOLOGIN group, neither a superuser nor BYPASSRLS'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT pg_catalog.pg_has_role('consentvault_app', 'consentvault_projection', 'MEMBER') THEN
        RAISE EXCEPTION 'consentvault migration 0093 refused: consentvault_app is not a member of consentvault_projection. As a '
                        'superuser run: GRANT consentvault_projection TO consentvault_app'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
END
$$;

CREATE FUNCTION consentvault.sync_projection_grants() RETURNS void
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    unreadable text[] := ARRAY['capture_source', 'brand', 'disclosure', 'channel', 'purpose', 'credential', 'tenancy_setting', 'retention_policy'];
    definers text[] := ARRAY['current_org', 'home_org', 'enter_org', 'current_token_scopes', 'current_token_claims', 'may_read_evidence',
                             'ledger_lock_key', 'raw_post_lock_key', 'raw_post_head', 'ledger_head', 'contact_key_of', 'receipt_of',
                             'request_counted', 'arrival_at', 'arrival_key', 'arrival_place', 'arrival_post_seq',
                             'sync_targets', 'sync_echo_targets', 'sync_advance_state', 'sync_enqueue', 'sync_enqueue_refresh',
                             'confirmation_enqueue', 'record_upsert', 'record_index_refresh', 'record_display_write',
                             'resolve_site_key', 'resolve_site_key_times', 'wording_as_of'];
    r record;
    c record;
    p text;
BEGIN
    GRANT USAGE ON SCHEMA consentvault TO consentvault_projection;
    FOR r IN SELECT cl.oid, cl.relname, cl.relkind FROM pg_class cl JOIN pg_namespace n ON n.oid = cl.relnamespace
              WHERE n.nspname = 'consentvault' AND cl.relkind IN ('r', 'p', 'v', 'm') AND cl.relname <> ALL (unreadable)
              ORDER BY cl.relname LOOP
        IF r.relname = 'organization' THEN
            EXECUTE 'GRANT SELECT (org_id, status) ON consentvault.organization TO consentvault_projection';
            CONTINUE;
        END IF;
        FOREACH p IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'] LOOP
            IF has_table_privilege('consentvault_app', r.oid, p) THEN
                EXECUTE format('GRANT %s ON consentvault.%I TO consentvault_projection', p, r.relname);
            ELSIF p <> 'DELETE' THEN
                FOR c IN SELECT a.attname FROM pg_attribute a WHERE a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped LOOP
                    IF has_column_privilege('consentvault_app', r.oid, c.attname, p) THEN
                        EXECUTE format('GRANT %s (%I) ON consentvault.%I TO consentvault_projection', p, c.attname, r.relname);
                    END IF;
                END LOOP;
            END IF;
        END LOOP;
    END LOOP;
    FOR r IN SELECT cl.oid, cl.relname FROM pg_class cl JOIN pg_namespace n ON n.oid = cl.relnamespace
              WHERE n.nspname = 'consentvault' AND cl.relkind = 'S' LOOP
        IF has_sequence_privilege('consentvault_app', r.oid, 'USAGE') THEN
            EXECUTE format('GRANT USAGE ON SEQUENCE consentvault.%I TO consentvault_projection', r.relname);
        END IF;
    END LOOP;
    -- A security-definer function runs with its owner's rights and so is not bound by this role's missing reads: the role may call
    -- only the named few below (the projection's own plumbing and the identity lookups), every one pinned by body hash in
    -- tests/isolation/test_projection_login.py. Every ordinary (invoker) function the app may call is bound by this role's rights
    -- and is granted as the app has it.
    FOR r IN SELECT pr.oid, pr.proname, pr.prosecdef, pr.oid::regprocedure::text AS sig FROM pg_proc pr
               JOIN pg_namespace n ON n.oid = pr.pronamespace
              WHERE n.nspname = 'consentvault' AND pr.prokind IN ('f', 'p') LOOP
        IF has_function_privilege('consentvault_app', r.oid, 'EXECUTE') AND (NOT r.prosecdef OR r.proname = ANY (definers)) THEN
            EXECUTE format('GRANT EXECUTE ON ROUTINE %s TO consentvault_projection', r.sig);
        ELSE
            EXECUTE format('REVOKE EXECUTE ON ROUTINE %s FROM consentvault_projection', r.sig);
        END IF;
    END LOOP;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_projection_grants() FROM PUBLIC;

-- The one read of the wording table the projection keeps, for a post stored by a build that did not store the wording fact beside it:
-- whether the organisation had the wording, and what it names, AS OF the post's stored arrival (wording is immutable, so first_seen_at
-- against the arrival is the answer the intake would have given). Security definer, read-only, one organisation, pinned by body hash.
CREATE FUNCTION consentvault.wording_as_of(p_sha text, p_as_of timestamptz)
    RETURNS TABLE (known boolean, brand_ids uuid[], channels text[], purposes text[])
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT true, d.brand_ids, d.channels, d.purposes FROM consentvault.disclosure d
     WHERE d.org_id OPERATOR(pg_catalog.=) consentvault.current_org() AND d.sha256 OPERATOR(pg_catalog.=) p_sha
       AND d.first_seen_at OPERATOR(pg_catalog.<=) p_as_of;
$$;
REVOKE ALL ON FUNCTION consentvault.wording_as_of(text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.wording_as_of(text, timestamptz) TO consentvault_app;

SELECT consentvault.sync_projection_grants();
