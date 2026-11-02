-- Role layout after the third adversarial review (the operator console no longer connects as the schema owner).
--
-- The roles (made once per cluster by a superuser: docker/initdb/10-roles.sh, or the managed database's master user):
--   * the schema owner (the database's owner, consentvault_owner in the reference stack) owns every table, sequence and
--     owner-rights function and is NOLOGIN. Nobody connects as it.
--   * the migrator logs in, is a member of the owner, and runs every migration under SET ROLE to it (db.migrate).
--   * consentvault_console holds only what the operator console and the operator jobs need (section 1); its login
--     (consentvault_operator_login) owns nothing, so it can neither switch a trigger off nor replace a function.
--   * consentvault_app and consentvault_worker keep their grants.
-- Disabling or dropping a trigger on a vault table is refused for every role but a superuser by the trigger guard
-- (docker/initdb/20-trigger-guard.sql, installed by a superuser at init). owner_rights_violations() now also reports a
-- schema owner that can log in, an object not owned by the schema owner, an operator console role that can bypass row
-- security or act as the owner, and a missing or disabled trigger guard; require_multi_tenant() refuses on any of them.
--
-- release_hold_as_operator takes the operator from the signed operator session: the tenant token the console entered the
-- organisation with names it (credential 'operator:<id>', erasure.operator_org). Its last parameter is a
-- cross-check only; a different name refuses. It runs with the owner's rights and only consentvault_console may call it.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_console') THEN
        RAISE EXCEPTION 'consentvault migration 0019 refused: the role consentvault_console does not exist. As a superuser '
                        '(or the managed database master user) run: CREATE ROLE consentvault_console NOLOGIN; then see '
                        'docs/selfhost.md, "Roles", for the operator console login'
            USING ERRCODE = 'undefined_object';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_console' AND (rolsuper OR rolbypassrls)) THEN
        RAISE EXCEPTION 'consentvault migration 0019 refused: consentvault_console must be neither a superuser nor BYPASSRLS'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
END
$$;

-- 1. What the operator console may do ------------------------------------------------------------------------------------
GRANT USAGE ON SCHEMA consentvault TO consentvault_console;
-- Measured, not guessed: every statement the operator console's code ran across the whole suite (statement log of the
-- console login), kept only where the source issues it. The console is bound by row-level security on all of these,
-- and every guard trigger still fires for it. It holds no TRUNCATE, TRIGGER or REFERENCES, no UPDATE or DELETE on an
-- evidence table (event, seal, chain_head, disclosure, contact_key, audit_event, policy_attestation, policy_approval),
-- and no write on a hold's release columns (release_hold_as_operator writes them).
GRANT SELECT ON consentvault.tenancy_setting, consentvault.attestation_text, consentvault.audit_chain_breaks, consentvault.audit_event,
    consentvault.chain_head, consentvault.contact_key, consentvault.contact_log, consentvault.current_permission,
    consentvault.disclosure, consentvault.outbox, consentvault.policy_attestation,
    consentvault.review, consentvault.seal, consentvault.unsealed_events
    TO consentvault_console;
-- event: the restore re-ingests the stops a restored copy lost (an append; the append-only guard still binds it)
GRANT SELECT, INSERT ON consentvault.event, consentvault.brand, consentvault.channel, consentvault.destruction_record,
    consentvault.erasure_ledger_commit, consentvault.legal_hold, consentvault.org_fingerprint_secret,
    consentvault.policy_approval, consentvault.purpose, consentvault.retention_policy
    TO consentvault_console;
GRANT SELECT, INSERT, UPDATE ON consentvault.capture_source, consentvault.connected_system, consentvault.credential,
    consentvault.doc_checklist, consentvault.erasure_request, consentvault.evidence_object, consentvault.export_job,
    consentvault.invite, consentvault.legal_process, consentvault.offboarding_request, consentvault.operator_access,
    consentvault.org_key, consentvault.organization, consentvault.policy, consentvault.restore_run
    TO consentvault_console;
GRANT SELECT, UPDATE ON consentvault.operator_access_approval TO consentvault_console;
GRANT SELECT, INSERT, UPDATE, DELETE ON consentvault.member TO consentvault_console;

-- Owner-rights functions the console calls (entering an organisation, the lifecycle lock, erasure, the audit chains,
-- the operator's cross-organisation lists), and the functions its row-level policies evaluate.
GRANT EXECUTE ON FUNCTION consentvault.enter_org(text), consentvault.current_org(), consentvault.current_token_scopes(),
    consentvault.current_token_claims(), consentvault.may_read_audit(), consentvault.lifecycle_lock(),
    consentvault.erase_contact(text), consentvault.legal_hold_covering(text), consentvault.hold_disclosure(uuid),
    consentvault.ledger_head(), consentvault.ledger_lock_key(uuid), consentvault.contact_key_of(text),
    consentvault.append_audit(text, text, text, text, text, text, text),
    consentvault.append_platform_audit(text, text, text, text, text, text), consentvault.audit_head(),
    consentvault.platform_audit_head(), consentvault.evidence_org_ids(), consentvault.restore_org_ids(),
    consentvault.health_counts(), consentvault.source_last_events(), consentvault.invite_lookup(text),
    consentvault.session_memberships(text, text), consentvault.sync_system_bind_credential(uuid, uuid),
    consentvault.all_fingerprints(text[]), consentvault.may_read_evidence()
    TO consentvault_console;
-- A stop the restore re-ingests queues its pushes the way a capture does.
GRANT EXECUTE ON FUNCTION consentvault.sync_advance_state(uuid, text), consentvault.sync_targets(),
    consentvault.sync_enqueue(uuid, uuid, text, text, text, integer, bytea) TO consentvault_console;

-- 2. The operator who releases a hold comes from the signed operator session ---------------------------------------------
CREATE OR REPLACE FUNCTION consentvault.release_hold_as_operator(p_hold uuid, p_reason text, p_released_at timestamptz,
                                                                 p_ledger_seq bigint, p_operator_id text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c   record;
    op  text;
BEGIN
    SELECT * INTO c FROM consentvault.current_token_claims();
    IF NOT FOUND OR c.org_id IS NULL OR c.org_id IS DISTINCT FROM consentvault.current_org()
       OR c.credential_id IS NULL OR left(c.credential_id, 9) <> 'operator:' THEN
        RAISE EXCEPTION 'consentvault hold release refused: no operator session is entered'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    op := substr(c.credential_id, 10);
    IF length(op) NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'consentvault hold release refused: the operator session names no operator'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_operator_id IS NOT NULL AND p_operator_id <> op THEN
        RAISE EXCEPTION 'consentvault hold release refused: the named operator does not match the operator session'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN consentvault.release_hold_row(c.org_id, p_hold, 'operator', op, p_reason, p_released_at, p_ledger_seq);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.release_hold_as_operator(uuid, text, timestamptz, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.release_hold_as_operator(uuid, text, timestamptz, bigint, text)
    TO consentvault_console;

-- 3. The ownership check covers the role layout and the trigger guard ----------------------------------------------------
CREATE OR REPLACE FUNCTION consentvault.owner_rights_violations()
    RETURNS TABLE (object_kind text, object_name text, owner_name text, problem text)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH ns AS (
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
               ('consentvault_refuse_trigger_disable'::name, 'ddl_command_end'::name, 'refuse_trigger_disable'::name)
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
        OR pn.nspowner OPERATOR(pg_catalog.<>) ALL (ARRAY(SELECT oid FROM breakglass));
$$;
REVOKE ALL ON FUNCTION consentvault.owner_rights_violations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.owner_rights_violations() TO consentvault_app, consentvault_worker,
    consentvault_console;
