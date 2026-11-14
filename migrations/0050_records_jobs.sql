-- The records export worker runs as its own group role, consentvault_records_jobs, through a dedicated login (the pattern of
-- the integrity jobs, 0048). In multi-tenant mode a login without a tenant token sees no rows, so the worker takes one token
-- per organization from the database (dispatch_org_ids, dispatch_org_token: scope 'worker:records_exports') and builds that
-- organization's exports inside it.
--
-- What the group may do, and nothing more:
--   * list the organizations and take each one's token (dispatch_org_ids, dispatch_org_token), enter an organization with it
--     (enter_org, current_org, current_token_scopes), and answer the row-security checks the tables below run;
--   * read what building an export needs, under that token: the record list (record, record_index, record_display), the
--     organization's display key, the source, brand, channel and purpose names, the organization's name, and the event
--     columns and contact key a full export opens a contact point with (contact_key_of);
--   * write the export: its job row (status, counts, times, hash, failure cause) and the audit rows it owes
--     (append_audit, append_audit_detailed).
-- It holds no other function: no erase, no reveal, no record writer, no admin, no billing, no token signing. It holds no INSERT,
-- DELETE or TRUNCATE on any table, and UPDATE only on the columns of its own job row. Row security binds it like every role.
-- The records read scopes admit the token it takes ('worker:records_exports') only for a login in this group, so the sync
-- worker, which can take the same scope, still reads nothing.
--
-- The role is made once per cluster by a superuser (docker/initdb/10-roles.sh, or the managed database's master user).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_records_jobs') THEN
        RAISE EXCEPTION 'consentvault migration 0050 refused: the role consentvault_records_jobs does not exist. As a superuser '
                        '(or the managed database master user) run: CREATE ROLE consentvault_records_jobs NOLOGIN; then '
                        'create its login as a member of it (docs/deployment.md, "Roles")'
            USING ERRCODE = 'undefined_object';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_records_jobs'
                AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
        RAISE EXCEPTION 'consentvault migration 0050 refused: consentvault_records_jobs must be a NOLOGIN group, neither a '
                        'superuser nor BYPASSRLS'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION consentvault.may_read_evidence() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.event'::regclass)
        OR coalesce(current_setting('consentvault.org_token', true), '') = ''
        OR coalesce(consentvault.current_token_scopes() && ARRAY['gate_read', 'proof_read', 'admin'], false)
        OR (coalesce(consentvault.current_token_scopes()
                     && ARRAY['worker:seal', 'worker:verify_seals', 'worker:verify_chain', 'worker:anchor'], false)
            AND pg_has_role(current_user, 'consentvault_integrity', 'MEMBER'))
        OR (coalesce(consentvault.current_token_scopes() && ARRAY['worker:records_exports'], false)
            AND pg_has_role(current_user, 'consentvault_records_jobs', 'MEMBER'));
$$;

CREATE OR REPLACE FUNCTION consentvault.may_read_names() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.record_display'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'proof_read', 'records_read'], false)
        OR (coalesce(consentvault.current_token_scopes() && ARRAY['worker:records_exports'], false)
            AND pg_has_role(current_user, 'consentvault_records_jobs', 'MEMBER'));
$$;

CREATE OR REPLACE FUNCTION consentvault.may_read_records() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.record'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'developer', 'proof_read', 'records_read'], false)
        OR (coalesce(consentvault.current_token_scopes() && ARRAY['worker:records_exports'], false)
            AND pg_has_role(current_user, 'consentvault_records_jobs', 'MEMBER'));
$$;

CREATE OR REPLACE FUNCTION consentvault.may_read_display_key() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.org_display_key'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['worker:display_key'], false)
        OR (coalesce(consentvault.current_token_scopes() && ARRAY['worker:records_exports'], false)
            AND pg_has_role(current_user, 'consentvault_records_jobs', 'MEMBER'));
$$;

CREATE OR REPLACE FUNCTION consentvault.may_read_record_exports() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.record_export'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'proof_read', 'records_read'], false)
        OR (coalesce(consentvault.current_token_scopes() && ARRAY['worker:records_exports'], false)
            AND pg_has_role(current_user, 'consentvault_records_jobs', 'MEMBER'));
$$;

GRANT USAGE ON SCHEMA consentvault TO consentvault_records_jobs;
GRANT EXECUTE ON FUNCTION consentvault.dispatch_org_ids(text), consentvault.dispatch_org_token(text, uuid),
    consentvault.enter_org(text), consentvault.current_org(), consentvault.current_token_scopes(),
    consentvault.may_read_evidence(), consentvault.may_read_names(), consentvault.may_read_records(),
    consentvault.may_read_display_key(), consentvault.may_read_record_exports(), consentvault.contact_key_of(text),
    consentvault.append_audit(text, text, text, text, text, text, text),
    consentvault.append_audit_detailed(text, text, text, text, text, text, text, jsonb)
    TO consentvault_records_jobs;
GRANT SELECT ON consentvault.record, consentvault.record_index, consentvault.record_display, consentvault.org_display_key,
    consentvault.record_export, consentvault.channel, consentvault.purpose TO consentvault_records_jobs;
GRANT SELECT (org_id, source_id, name) ON consentvault.capture_source TO consentvault_records_jobs;
GRANT SELECT (org_id, brand_id) ON consentvault.brand TO consentvault_records_jobs;
GRANT SELECT (org_id, name) ON consentvault.organization TO consentvault_records_jobs;
GRANT SELECT (org_id, event_id, seq, contact_fp, contact_ct) ON consentvault.event TO consentvault_records_jobs;
GRANT UPDATE (status, row_count, progress_done, completed_at, expires_at, sha256, failed_cause)
    ON consentvault.record_export TO consentvault_records_jobs;
