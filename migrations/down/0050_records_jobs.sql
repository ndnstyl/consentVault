-- Undo 0050: the records read scopes go back to their 0048 and 0044 bodies, and the records jobs group loses every grant 0050
-- gave it. The role itself (made by a superuser) is left in place.
REVOKE UPDATE (status, row_count, progress_done, completed_at, expires_at, sha256, failed_cause)
    ON consentvault.record_export FROM consentvault_records_jobs;
REVOKE SELECT (org_id, event_id, seq, contact_fp, contact_ct) ON consentvault.event FROM consentvault_records_jobs;
REVOKE SELECT (org_id, name) ON consentvault.organization FROM consentvault_records_jobs;
REVOKE SELECT (org_id, brand_id) ON consentvault.brand FROM consentvault_records_jobs;
REVOKE SELECT (org_id, source_id, name) ON consentvault.capture_source FROM consentvault_records_jobs;
REVOKE SELECT ON consentvault.record, consentvault.record_index, consentvault.record_display, consentvault.org_display_key,
    consentvault.record_export, consentvault.channel, consentvault.purpose FROM consentvault_records_jobs;
REVOKE EXECUTE ON FUNCTION consentvault.dispatch_org_ids(text), consentvault.dispatch_org_token(text, uuid),
    consentvault.enter_org(text), consentvault.current_org(), consentvault.current_token_scopes(),
    consentvault.may_read_evidence(), consentvault.may_read_names(), consentvault.may_read_records(),
    consentvault.may_read_display_key(), consentvault.may_read_record_exports(), consentvault.contact_key_of(text),
    consentvault.append_audit(text, text, text, text, text, text, text),
    consentvault.append_audit_detailed(text, text, text, text, text, text, text, jsonb)
    FROM consentvault_records_jobs;
REVOKE USAGE ON SCHEMA consentvault FROM consentvault_records_jobs;

CREATE OR REPLACE FUNCTION consentvault.may_read_record_exports() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.record_export'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'proof_read', 'records_read'], false);
$$;
CREATE OR REPLACE FUNCTION consentvault.may_read_display_key() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.org_display_key'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['worker:display_key'], false);
$$;
CREATE OR REPLACE FUNCTION consentvault.may_read_records() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.record'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'developer', 'proof_read', 'records_read'], false);
$$;
CREATE OR REPLACE FUNCTION consentvault.may_read_names() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.record_display'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'proof_read', 'records_read'], false);
$$;
CREATE OR REPLACE FUNCTION consentvault.may_read_evidence() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.event'::regclass)
        OR coalesce(current_setting('consentvault.org_token', true), '') = ''
        OR coalesce(consentvault.current_token_scopes() && ARRAY['gate_read', 'proof_read', 'admin'], false)
        OR (coalesce(consentvault.current_token_scopes()
                     && ARRAY['worker:seal', 'worker:verify_seals', 'worker:verify_chain', 'worker:anchor'], false)
            AND pg_has_role(current_user, 'consentvault_integrity', 'MEMBER'));
$$;
