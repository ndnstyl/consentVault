-- Reverses 0005_admin.sql. Refuses while any admin-plane record exists (audit rows, invitations, policies, checklists,
-- retention, export jobs, channel and purpose lists, registered systems, wrapped fingerprint secrets, a developer
-- member, a trial or past_due organisation): a down migration never destroys evidence or a client's configuration.
--
-- Run it as a superuser (or a BYPASSRLS role), in one transaction, after down/0007_billing.sql if that is applied.
BEGIN;
SET LOCAL row_security = off;

DO $$
DECLARE
    n bigint;
    t text;
BEGIN
    IF to_regclass('consentvault.audit_event') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0005 refused: consentvault.audit_event is missing; 0005 is not applied';
    END IF;
    IF to_regclass('consentvault.org_status_history') IS NOT NULL THEN
        RAISE EXCEPTION 'consentvault down 0005 refused: run down/0007_billing.sql first';
    END IF;
    FOREACH t IN ARRAY ARRAY['audit_event', 'invite', 'policy', 'policy_approval', 'policy_attestation', 'doc_checklist',
                             'retention_policy', 'export_job', 'channel', 'purpose', 'org_fingerprint_secret'] LOOP
        EXECUTE format('SELECT count(*) FROM consentvault.%I', t) INTO n;
        IF n > 0 THEN
            RAISE EXCEPTION 'consentvault down 0005 refused: consentvault.% holds % row(s); export them first', t, n;
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM consentvault.connected_system WHERE name IS NOT NULL) THEN
        RAISE EXCEPTION 'consentvault down 0005 refused: registered connected systems exist';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.member WHERE role = 'developer') THEN
        RAISE EXCEPTION 'consentvault down 0005 refused: a developer member exists';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.organization WHERE status IN ('trial', 'past_due')) THEN
        RAISE EXCEPTION 'consentvault down 0005 refused: an organisation is in trial or past_due';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.disclosure WHERE supersedes_sha256 IS NOT NULL OR version_label IS NOT NULL
                  OR registered_by IS NOT NULL OR effective_from IS NOT NULL OR cardinality(brand_ids) > 0) THEN
        RAISE EXCEPTION 'consentvault down 0005 refused: wording versions carry admin-plane columns';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.capture_source WHERE name IS NOT NULL OR status <> 'active')
       OR EXISTS (SELECT 1 FROM consentvault.credential WHERE name IS NOT NULL OR site_key_id IS NOT NULL OR revoke_reason IS NOT NULL) THEN
        RAISE EXCEPTION 'consentvault down 0005 refused: sources or credentials carry admin-plane columns';
    END IF;
END
$$;

DROP POLICY audit_event_read_scope ON consentvault.audit_event;
DROP POLICY export_job_read_scope ON consentvault.export_job;
DROP VIEW consentvault.audit_chain_breaks;

DROP FUNCTION consentvault.may_read_audit();
DROP FUNCTION consentvault.current_token_claims();
DROP FUNCTION consentvault.health_counts();
DROP FUNCTION consentvault.source_last_events();
DROP FUNCTION consentvault.platform_audit_head();
DROP FUNCTION consentvault.audit_head();
DROP FUNCTION consentvault.append_platform_audit(text, text, text, text, text, text);
DROP FUNCTION consentvault.append_audit(text, text, text, text, text, text, text);
DROP FUNCTION consentvault.session_memberships(text, text);
DROP FUNCTION consentvault.invite_lookup(text);

DROP TABLE consentvault.audit_event;
DROP FUNCTION consentvault.audit_chain_guard();
DROP FUNCTION consentvault.audit_row_hash(text, uuid, bigint, text, text, text, text, text, text, text, timestamptz);
DROP TABLE consentvault.export_job;
DROP FUNCTION consentvault.export_job_guard();

DO $$
DECLARE
    other int;
BEGIN
    SELECT count(*) INTO other FROM information_schema.columns
     WHERE table_schema = 'consentvault' AND table_name = 'connected_system'
       AND column_name NOT IN ('org_id', 'system_id', 'kind', 'connector', 'config', 'credentials_ct', 'status', 'created_at',
                               'name', 'endpoint', 'signature', 'contact_form', 'retry_window_hours', 'public_key', 'created_by',
                               'last_delivery_at', 'last_test');
    IF other = 0 THEN
        DROP TABLE consentvault.connected_system;
    ELSE
        -- another lane owns the table; take back only what this migration added
        DROP INDEX IF EXISTS consentvault.connected_system_org_name_idx;
        ALTER TABLE consentvault.connected_system
            DROP CONSTRAINT IF EXISTS connected_system_kind_admin, DROP CONSTRAINT IF EXISTS connected_system_status_admin,
            DROP CONSTRAINT IF EXISTS connected_system_endpoint_https, DROP CONSTRAINT IF EXISTS connected_system_signature_admin,
            DROP CONSTRAINT IF EXISTS connected_system_contact_form_admin, DROP CONSTRAINT IF EXISTS connected_system_retry_admin;
    END IF;
END
$$;

DROP TABLE consentvault.retention_policy;
DROP TABLE consentvault.rule_reference;
DROP TABLE consentvault.doc_checklist;
DROP FUNCTION consentvault.doc_checklist_guard();
DROP TABLE consentvault.policy_attestation;
DROP TABLE consentvault.policy_approval;
DROP TABLE consentvault.policy;
DROP FUNCTION consentvault.policy_guard();
DROP TABLE consentvault.attestation_text;

DROP INDEX consentvault.disclosure_one_successor_idx;
ALTER TABLE consentvault.disclosure
    DROP COLUMN version_label, DROP COLUMN supersedes_sha256, DROP COLUMN effective_from,
    DROP COLUMN registered_by, DROP COLUMN brand_ids;

DROP TABLE consentvault.invite;
DROP FUNCTION consentvault.invite_guard();
DROP TABLE consentvault.purpose;
DROP TABLE consentvault.channel;
DROP TABLE consentvault.org_fingerprint_secret;

ALTER TABLE consentvault.credential
    DROP COLUMN name, DROP COLUMN created_by, DROP COLUMN last_used_at, DROP COLUMN revoked_by,
    DROP COLUMN revoke_reason, DROP COLUMN site_key_id;
DROP INDEX consentvault.capture_source_org_name_idx;
ALTER TABLE consentvault.capture_source
    DROP COLUMN name, DROP COLUMN status, DROP COLUMN retired_at, DROP COLUMN created_by;
DROP INDEX consentvault.brand_org_name_idx;
ALTER TABLE consentvault.brand DROP COLUMN created_by;

DROP TRIGGER member_last_admin_guard ON consentvault.member;
DROP FUNCTION consentvault.member_last_admin_guard();
DROP INDEX consentvault.member_org_email_idx;
ALTER TABLE consentvault.member DROP CONSTRAINT member_org_member_id_key;
ALTER TABLE consentvault.member
    DROP COLUMN member_id, DROP COLUMN email_norm, DROP COLUMN display_name, DROP COLUMN last_sign_in_at,
    DROP COLUMN invited_by;
ALTER TABLE consentvault.member DROP CONSTRAINT member_role_check;
ALTER TABLE consentvault.member ADD CONSTRAINT member_role_check CHECK (role IN ('admin', 'compliance_viewer'));

REVOKE INSERT, DELETE ON consentvault.member FROM consentvault_app;
REVOKE INSERT ON consentvault.brand FROM consentvault_app;
REVOKE INSERT ON consentvault.capture_source FROM consentvault_app;
REVOKE INSERT ON consentvault.credential FROM consentvault_app;

ALTER TABLE consentvault.organization DROP CONSTRAINT organization_status_check;
ALTER TABLE consentvault.organization ADD CONSTRAINT organization_status_check
    CHECK (status IN ('active', 'suspended', 'offboarding', 'closed'));

REVOKE SELECT (org_id, event_id, received_at, seq, source_id) ON consentvault.event FROM consentvault_operator;
REVOKE SELECT (org_id, event_id) ON consentvault.seal FROM consentvault_operator;
REVOKE EXECUTE ON FUNCTION consentvault.current_org() FROM consentvault_operator;

COMMIT;
