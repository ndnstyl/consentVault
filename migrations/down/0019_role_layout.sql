-- Reverses 0019_role_layout.sql. Run it as a superuser, in one transaction. The roles themselves (the NOLOGIN owner, the
-- migrator, consentvault_console and its login) and the trigger guard are cluster or database objects made outside the
-- migrations; they are left as they are.
BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                    WHERE n.nspname = 'consentvault' AND p.proname = 'release_hold_as_operator' AND p.prosecdef) THEN
        RAISE EXCEPTION 'consentvault down 0019 refused: 0019 is not applied';
    END IF;
END
$$;

-- The release function goes back to its 0016 shape (the operator named by the caller, owner connection only).
-- It was SECURITY DEFINER under 0019; it is the caller's rights again.
CREATE OR REPLACE FUNCTION consentvault.release_hold_as_operator(p_hold uuid, p_reason text, p_released_at timestamptz,
                                                      p_ledger_seq bigint, p_operator_id text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.current_org();
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault hold release refused: no organization is entered'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_operator_id IS NULL OR length(p_operator_id) NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'consentvault hold release refused: the operator id is missing or malformed'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN consentvault.release_hold_row(org, p_hold, 'operator', p_operator_id, p_reason, p_released_at, p_ledger_seq);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.release_hold_as_operator(uuid, text, timestamptz, bigint, text) FROM PUBLIC;


-- The ownership check goes back to its 0008 shape.
CREATE OR REPLACE FUNCTION consentvault.owner_rights_violations()
    RETURNS TABLE (object_kind text, object_name text, owner_name text, problem text)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH ns AS (
        SELECT n.oid, n.nspowner FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.=) 'consentvault'
    ), op AS (
        SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) 'consentvault_operator'
    )
    SELECT 'schema', 'consentvault', r.rolname, 'the schema owner is a superuser or BYPASSRLS'
      FROM ns JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) ns.nspowner
     WHERE r.rolsuper OR r.rolbypassrls
    UNION ALL
    SELECT 'role', 'consentvault_operator', r.rolname, 'the operator role is a superuser'
      FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) 'consentvault_operator' AND r.rolsuper
    UNION ALL
    SELECT 'function', p.oid::pg_catalog.regprocedure::pg_catalog.text, r.rolname,
           'an owner-rights function is owned by a role other than the schema owner or consentvault_operator'
      FROM pg_catalog.pg_proc p
      JOIN ns ON p.pronamespace OPERATOR(pg_catalog.=) ns.oid
      JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) p.proowner
     WHERE p.prosecdef
       AND p.proowner OPERATOR(pg_catalog.<>) ns.nspowner
       AND p.proowner OPERATOR(pg_catalog.<>) ALL (ARRAY(SELECT oid FROM op))
    UNION ALL
    SELECT 'table', c.oid::pg_catalog.regclass::pg_catalog.text, r.rolname,
           'a row-secured table is owned by a superuser or BYPASSRLS role, or does not FORCE row-level security'
      FROM pg_catalog.pg_class c
      JOIN ns ON c.relnamespace OPERATOR(pg_catalog.=) ns.oid
      JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) c.relowner
     WHERE c.relkind IN ('r', 'p') AND c.relrowsecurity
       AND (r.rolsuper OR r.rolbypassrls OR NOT c.relforcerowsecurity);
$$;
REVOKE ALL ON FUNCTION consentvault.owner_rights_violations() FROM PUBLIC, consentvault_console;
GRANT EXECUTE ON FUNCTION consentvault.owner_rights_violations() TO consentvault_app, consentvault_worker;

REVOKE ALL ON consentvault.tenancy_setting, consentvault.attestation_text, consentvault.audit_chain_breaks, consentvault.audit_event, consentvault.chain_head, consentvault.contact_key, consentvault.contact_log, consentvault.current_permission, consentvault.disclosure, consentvault.outbox, consentvault.policy_attestation, consentvault.review, consentvault.seal, consentvault.unsealed_events FROM consentvault_console;
REVOKE ALL ON consentvault.event, consentvault.brand, consentvault.channel, consentvault.destruction_record, consentvault.erasure_ledger_commit, consentvault.legal_hold, consentvault.org_fingerprint_secret, consentvault.policy_approval, consentvault.purpose, consentvault.retention_policy FROM consentvault_console;
REVOKE ALL ON consentvault.capture_source, consentvault.connected_system, consentvault.credential, consentvault.doc_checklist, consentvault.erasure_request, consentvault.evidence_object, consentvault.export_job, consentvault.invite, consentvault.legal_process, consentvault.offboarding_request, consentvault.operator_access, consentvault.org_key, consentvault.organization, consentvault.policy, consentvault.restore_run FROM consentvault_console;
REVOKE ALL ON consentvault.operator_access_approval FROM consentvault_console;
REVOKE ALL ON consentvault.member FROM consentvault_console;
REVOKE ALL ON FUNCTION consentvault.enter_org(text), consentvault.current_org(), consentvault.current_token_scopes(), consentvault.current_token_claims(), consentvault.may_read_audit(), consentvault.lifecycle_lock(), consentvault.erase_contact(text), consentvault.legal_hold_covering(text), consentvault.hold_disclosure(uuid), consentvault.ledger_head(), consentvault.ledger_lock_key(uuid), consentvault.contact_key_of(text), consentvault.append_audit(text, text, text, text, text, text, text), consentvault.append_platform_audit(text, text, text, text, text, text), consentvault.audit_head(), consentvault.platform_audit_head(), consentvault.evidence_org_ids(), consentvault.restore_org_ids(), consentvault.health_counts(), consentvault.source_last_events(), consentvault.invite_lookup(text), consentvault.session_memberships(text, text), consentvault.sync_system_bind_credential(uuid, uuid), consentvault.all_fingerprints(text[]), consentvault.may_read_evidence() FROM consentvault_console;
REVOKE ALL ON FUNCTION consentvault.sync_advance_state(uuid, text), consentvault.sync_targets(), consentvault.sync_enqueue(uuid, uuid, text, text, text, integer, bytea) FROM consentvault_console;
REVOKE ALL ON FUNCTION consentvault.release_hold_as_operator(uuid, text, timestamptz, bigint, text) FROM consentvault_console;
-- Anything a later migration granted the console (run out of order, before that migration's own down) goes as well.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT c.oid::regclass AS obj FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'consentvault' AND c.relkind IN ('r', 'p', 'v', 'm', 'S') LOOP
        EXECUTE format('REVOKE ALL ON %s FROM consentvault_console', r.obj);
    END LOOP;
    FOR r IN SELECT p.oid::regprocedure AS obj FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'consentvault' LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM consentvault_console', r.obj);
    END LOOP;
END
$$;
REVOKE ALL ON SCHEMA consentvault FROM consentvault_console;
COMMIT;
