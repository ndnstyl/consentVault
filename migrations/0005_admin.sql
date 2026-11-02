-- Admin plane: members and invitations, wording versions, policies with attestation, checklists, retention, connected
-- system registrations, the per-organisation audit chain and the platform chain, and the evidence export job table.
--
-- Everything here is tenant data behind the same row-level security as the rest of the vault: org_id NOT NULL, every
-- policy compares org_id with (SELECT consentvault.current_org()), every foreign key includes org_id. Two platform
-- tables (attestation_text, rule_reference) carry no org_id and are read-only to tenants.
--
-- Owner-rights functions here are written to run as consentvault_operator (BYPASSRLS) where they must read across
-- one organisation's rows without a tenant's scope. Because that role bypasses row security, every such function that
-- is meant for a tenant filters on current_org() itself and never takes an organisation argument. The two pre-tenant
-- lookups (invite_lookup, session_memberships) answer for one token digest or one identity at a time, the same shape
-- as resolve_credential and resolve_member.

-- Organisation status list: trial and past_due join the four 0002 values (billing refines the transitions) ----------
ALTER TABLE consentvault.organization DROP CONSTRAINT organization_status_check;
ALTER TABLE consentvault.organization ADD CONSTRAINT organization_status_check
    CHECK (status IN ('trial', 'active', 'past_due', 'suspended', 'offboarding', 'closed'));

-- Members ---------------------------------------------------------------------------------------------------------
ALTER TABLE consentvault.member DROP CONSTRAINT member_role_check;
ALTER TABLE consentvault.member ADD CONSTRAINT member_role_check CHECK (role IN ('admin', 'developer', 'compliance_viewer'));
ALTER TABLE consentvault.member
    ADD COLUMN member_id        uuid NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN email_norm       text CHECK (email_norm IS NULL OR length(email_norm) BETWEEN 3 AND 320),
    ADD COLUMN display_name     text CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 200),
    ADD COLUMN last_sign_in_at  timestamptz,
    ADD COLUMN invited_by       uuid;
ALTER TABLE consentvault.member ADD CONSTRAINT member_org_member_id_key UNIQUE (org_id, member_id);
CREATE UNIQUE INDEX member_org_email_idx ON consentvault.member (org_id, email_norm) WHERE email_norm IS NOT NULL;

-- The last admin of an organisation is never removed or demoted. The lock serialises two admins demoting each other.
CREATE FUNCTION consentvault.member_last_admin_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.role OPERATOR(pg_catalog.=) 'admin'
       AND (TG_OP OPERATOR(pg_catalog.=) 'DELETE' OR NEW.role OPERATOR(pg_catalog.<>) 'admin') THEN
        PERFORM pg_advisory_xact_lock(hashtext('consentvault.members:' || OLD.org_id::text));
        IF NOT EXISTS (SELECT 1 FROM consentvault.member m
                        WHERE m.org_id OPERATOR(pg_catalog.=) OLD.org_id AND m.role OPERATOR(pg_catalog.=) 'admin'
                          AND m.member_id OPERATOR(pg_catalog.<>) OLD.member_id) THEN
            RAISE EXCEPTION 'consentvault last_admin: the change would leave the organisation with no admin'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    RETURN CASE WHEN TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN OLD ELSE NEW END;
END;
$$;
CREATE TRIGGER member_last_admin_guard BEFORE UPDATE OR DELETE ON consentvault.member
    FOR EACH ROW EXECUTE FUNCTION consentvault.member_last_admin_guard();

-- Brands, sources, credentials ------------------------------------------------------------------------------------
ALTER TABLE consentvault.brand ADD COLUMN created_by uuid;
CREATE UNIQUE INDEX brand_org_name_idx ON consentvault.brand (org_id, lower(display_name));

ALTER TABLE consentvault.capture_source
    ADD COLUMN name       text CHECK (name IS NULL OR length(name) BETWEEN 1 AND 200),
    ADD COLUMN status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
    ADD COLUMN retired_at timestamptz,
    ADD COLUMN created_by uuid;
CREATE UNIQUE INDEX capture_source_org_name_idx ON consentvault.capture_source (org_id, lower(name)) WHERE name IS NOT NULL;

ALTER TABLE consentvault.credential
    ADD COLUMN name           text CHECK (name IS NULL OR length(name) BETWEEN 1 AND 200),
    ADD COLUMN created_by     uuid,
    ADD COLUMN last_used_at   timestamptz,
    ADD COLUMN revoked_by     uuid,
    ADD COLUMN revoke_reason  text CHECK (revoke_reason IS NULL OR length(revoke_reason) BETWEEN 1 AND 500),
    ADD COLUMN site_key_id    text UNIQUE CHECK (site_key_id IS NULL OR site_key_id ~ '^cv_site_[A-Za-z0-9_-]{16,64}$');

-- The organisation's fingerprint secret, wrapped by the org key. Never derived from another key, never rotated.
CREATE TABLE consentvault.org_fingerprint_secret (
    org_id     uuid PRIMARY KEY REFERENCES consentvault.organization (org_id),
    wrapped    bytea NOT NULL CHECK (octet_length(wrapped) > 0),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER org_fingerprint_secret_append_only BEFORE UPDATE OR DELETE ON consentvault.org_fingerprint_secret
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();

-- Channels and purposes the operator configured for the organisation ----------------------------------------------
CREATE TABLE consentvault.channel (
    org_id     uuid NOT NULL REFERENCES consentvault.organization (org_id),
    channel    text NOT NULL CHECK (channel ~ '^[a-z][a-z_]{0,31}$'),
    label      text NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, channel)
);
CREATE TABLE consentvault.purpose (
    org_id      uuid NOT NULL REFERENCES consentvault.organization (org_id),
    purpose     text NOT NULL CHECK (purpose ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    label       text NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, purpose)
);

-- Invitations -----------------------------------------------------------------------------------------------------
-- Single use, seven days, bound to the invited address; the token is stored only as a digest and never returned.
CREATE TABLE consentvault.invite (
    org_id              uuid NOT NULL REFERENCES consentvault.organization (org_id),
    invite_id           uuid NOT NULL DEFAULT gen_random_uuid(),
    token_digest        text NOT NULL UNIQUE CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    email_norm          text NOT NULL CHECK (length(email_norm) BETWEEN 3 AND 320),
    role                text NOT NULL CHECK (role IN ('admin', 'developer', 'compliance_viewer')),
    invited_by          uuid,
    invited_by_operator text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    accepted_at         timestamptz,
    accepted_member_id  uuid,
    withdrawn_at        timestamptz,
    PRIMARY KEY (org_id, invite_id),
    CONSTRAINT invite_life CHECK (expires_at > created_at AND expires_at <= created_at + interval '7 days'),
    CONSTRAINT invite_one_ending CHECK (NOT (accepted_at IS NOT NULL AND withdrawn_at IS NOT NULL))
);
CREATE UNIQUE INDEX invite_one_open_per_address_idx ON consentvault.invite (org_id, email_norm)
    WHERE accepted_at IS NULL AND withdrawn_at IS NULL;

-- Only the status columns move, each once.
CREATE FUNCTION consentvault.invite_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.invite is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.org_id, NEW.invite_id, NEW.token_digest, NEW.email_norm, NEW.role, NEW.invited_by, NEW.invited_by_operator,
        NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM (OLD.org_id, OLD.invite_id, OLD.token_digest, OLD.email_norm, OLD.role, OLD.invited_by,
        OLD.invited_by_operator, OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'consentvault.invite: only accepted_at, accepted_member_id and withdrawn_at may change'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (OLD.accepted_at IS NOT NULL AND NEW.accepted_at IS DISTINCT FROM OLD.accepted_at)
       OR (OLD.withdrawn_at IS NOT NULL AND NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at)
       OR (OLD.accepted_member_id IS NOT NULL AND NEW.accepted_member_id IS DISTINCT FROM OLD.accepted_member_id) THEN
        RAISE EXCEPTION 'consentvault.invite: a status column is set once' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER invite_guard BEFORE UPDATE OR DELETE ON consentvault.invite
    FOR EACH ROW EXECUTE FUNCTION consentvault.invite_guard();
CREATE TRIGGER invite_no_truncate BEFORE TRUNCATE ON consentvault.invite
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Wording versions (the disclosure table stays append-only; a successor is a new row, the link back is derived) ------
ALTER TABLE consentvault.disclosure
    ADD COLUMN version_label     text,
    ADD COLUMN supersedes_sha256 text CHECK (supersedes_sha256 IS NULL OR supersedes_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN effective_from    timestamptz,
    ADD COLUMN registered_by     uuid,
    ADD COLUMN brand_ids         uuid[] NOT NULL DEFAULT '{}';
CREATE UNIQUE INDEX disclosure_one_successor_idx ON consentvault.disclosure (org_id, supersedes_sha256)
    WHERE supersedes_sha256 IS NOT NULL;

-- Policies --------------------------------------------------------------------------------------------------------
-- Platform: the drafted attestation, one row per version, read-only to tenants. The text states who is responsible for
-- the policy and that counsel review is recommended and not required; it states no legal conclusion.
CREATE TABLE consentvault.attestation_text (
    version      integer PRIMARY KEY CHECK (version >= 1),
    text         text NOT NULL CHECK (length(text) > 0),
    sha256       text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    published_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT attestation_text_digest CHECK (sha256 = encode(sha256(convert_to(text, 'UTF8')), 'hex'))
);
CREATE TRIGGER attestation_text_append_only BEFORE UPDATE OR DELETE ON consentvault.attestation_text
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER attestation_text_no_truncate BEFORE TRUNCATE ON consentvault.attestation_text
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();
INSERT INTO consentvault.attestation_text (version, text, sha256)
SELECT 1, t, encode(sha256(convert_to(t, 'UTF8')), 'hex')
FROM (SELECT 'I am an administrator of this organisation and I am authorised to approve this policy for it. '
          || 'I understand that this policy is my organisation''s own mapping from the evidence status ConsentVault reports '
          || 'to proceed or hold, that ConsentVault records evidence and does not decide whether any contact is permitted, '
          || 'and that my organisation is responsible for the legal sufficiency of this policy. '
          || 'I understand that review of this policy by my organisation''s counsel is recommended and is not required.' AS t) v;

CREATE TABLE consentvault.policy (
    org_id             uuid NOT NULL REFERENCES consentvault.organization (org_id),
    version            integer NOT NULL CHECK (version >= 1),
    rules              jsonb NOT NULL,
    status             text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved', 'retired')),
    template_ref       text,
    based_on_version   integer,
    created_by         uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    approved_by        uuid,
    approved_at        timestamptz,
    retired_at         timestamptz,
    retired_by_version integer,
    PRIMARY KEY (org_id, version),
    CONSTRAINT policy_approved_shape CHECK ((status = 'draft') = (approved_at IS NULL)),
    CONSTRAINT policy_retired_shape CHECK ((status = 'retired') = (retired_at IS NOT NULL))
);
-- At most one policy in force per organisation; approving a version retires the previous one in the same transaction.
CREATE UNIQUE INDEX policy_one_in_force_idx ON consentvault.policy (org_id) WHERE status = 'approved';

CREATE FUNCTION consentvault.policy_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.policy is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status OPERATOR(pg_catalog.<>) 'draft' AND NEW.rules IS DISTINCT FROM OLD.rules THEN
        RAISE EXCEPTION 'consentvault.policy: an approved or retired version never changes' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status
       AND NOT ((OLD.status OPERATOR(pg_catalog.=) 'draft' AND NEW.status OPERATOR(pg_catalog.=) 'approved')
             OR (OLD.status OPERATOR(pg_catalog.=) 'approved' AND NEW.status OPERATOR(pg_catalog.=) 'retired')) THEN
        RAISE EXCEPTION 'consentvault.policy: status moves draft to approved to retired only' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.org_id, NEW.version, NEW.template_ref, NEW.based_on_version, NEW.created_by, NEW.created_at)
       IS DISTINCT FROM (OLD.org_id, OLD.version, OLD.template_ref, OLD.based_on_version, OLD.created_by, OLD.created_at) THEN
        RAISE EXCEPTION 'consentvault.policy: identity columns never change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER policy_guard BEFORE UPDATE OR DELETE ON consentvault.policy
    FOR EACH ROW EXECUTE FUNCTION consentvault.policy_guard();
CREATE TRIGGER policy_no_truncate BEFORE TRUNCATE ON consentvault.policy
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

CREATE TABLE consentvault.policy_approval (
    org_id              uuid NOT NULL,
    version             integer NOT NULL,
    approval_id         uuid NOT NULL DEFAULT gen_random_uuid(),
    approved_by         uuid NOT NULL,
    approved_at         timestamptz NOT NULL DEFAULT now(),
    attestation_version integer NOT NULL,
    attestation_sha256  text NOT NULL CHECK (attestation_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (org_id, version),
    UNIQUE (org_id, approval_id),
    FOREIGN KEY (org_id, version) REFERENCES consentvault.policy (org_id, version)
);

-- What the approver accepted, word for word.
CREATE TABLE consentvault.policy_attestation (
    org_id              uuid NOT NULL,
    version             integer NOT NULL,
    attestation_version integer NOT NULL,
    attestation_text    text NOT NULL,
    attestation_sha256  text NOT NULL CHECK (attestation_sha256 ~ '^[0-9a-f]{64}$'),
    approved_by         uuid NOT NULL,
    approved_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, version),
    FOREIGN KEY (org_id, version) REFERENCES consentvault.policy (org_id, version),
    CONSTRAINT policy_attestation_digest CHECK (attestation_sha256 = encode(sha256(convert_to(attestation_text, 'UTF8')), 'hex'))
);
CREATE TRIGGER policy_approval_append_only BEFORE UPDATE OR DELETE ON consentvault.policy_approval
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER policy_attestation_append_only BEFORE UPDATE OR DELETE ON consentvault.policy_attestation
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();

-- Checklists (documentation completeness, never a legal test) -------------------------------------------------------
CREATE TABLE consentvault.doc_checklist (
    org_id      uuid NOT NULL REFERENCES consentvault.organization (org_id),
    version     integer NOT NULL CHECK (version >= 1),
    kind        text NOT NULL CHECK (kind IN ('pewc', 'custom')),
    label       text NOT NULL CHECK (length(label) BETWEEN 1 AND 200),
    status      text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved')),
    elements    jsonb NOT NULL CHECK (jsonb_typeof(elements) = 'array' AND jsonb_array_length(elements) >= 1),
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    approved_by uuid,
    approved_at timestamptz,
    PRIMARY KEY (org_id, version),
    CONSTRAINT doc_checklist_approved_shape CHECK ((status = 'approved') = (approved_at IS NOT NULL))
);
CREATE FUNCTION consentvault.doc_checklist_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.doc_checklist is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status OPERATOR(pg_catalog.=) 'approved' THEN
        RAISE EXCEPTION 'consentvault.doc_checklist: an approved version never changes' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.org_id, NEW.version, NEW.kind, NEW.created_by, NEW.created_at)
       IS DISTINCT FROM (OLD.org_id, OLD.version, OLD.kind, OLD.created_by, OLD.created_at) THEN
        RAISE EXCEPTION 'consentvault.doc_checklist: identity columns never change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER doc_checklist_guard BEFORE UPDATE OR DELETE ON consentvault.doc_checklist
    FOR EACH ROW EXECUTE FUNCTION consentvault.doc_checklist_guard();
CREATE TRIGGER doc_checklist_no_truncate BEFORE TRUNCATE ON consentvault.doc_checklist
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Rule references: a citation, an official link and a review date, never a summary. Platform table, read-only. -------
CREATE TABLE consentvault.rule_reference (
    ref_id           uuid NOT NULL DEFAULT gen_random_uuid(),
    version          integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    jurisdiction     text NOT NULL CHECK (length(jurisdiction) BETWEEN 2 AND 64),
    citation         text NOT NULL CHECK (length(citation) BETWEEN 1 AND 200),
    source_url       text NOT NULL CHECK (source_url ~ '^https://'),
    last_reviewed_on date,
    PRIMARY KEY (ref_id, version)
);
CREATE TRIGGER rule_reference_append_only BEFORE UPDATE OR DELETE ON consentvault.rule_reference
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
-- last_reviewed_on stays NULL: nobody on the platform side has reviewed the link yet, and the portal shows that.
INSERT INTO consentvault.rule_reference (jurisdiction, citation, source_url)
VALUES ('US federal', '47 CFR 64.1200', 'https://www.ecfr.gov/current/title-47/chapter-I/subchapter-B/part-64/subpart-L/section-64.1200');

-- Retention -------------------------------------------------------------------------------------------------------
CREATE TABLE consentvault.retention_policy (
    org_id                 uuid NOT NULL REFERENCES consentvault.organization (org_id),
    version                integer NOT NULL CHECK (version >= 1),
    evidence_years         integer NOT NULL CHECK (evidence_years BETWEEN 1 AND 100),
    platform_minimum_years integer NOT NULL CHECK (platform_minimum_years >= 1),
    reason                 text CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 500),
    set_by                 uuid,
    applies_from           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, version),
    CONSTRAINT retention_at_or_above_minimum CHECK (evidence_years >= platform_minimum_years)
);
CREATE TRIGGER retention_policy_append_only BEFORE UPDATE OR DELETE ON consentvault.retention_policy
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();

-- Connected system registrations (the sync lane adds the delivery tables; both lanes may have made this table) ------
CREATE TABLE IF NOT EXISTS consentvault.connected_system (
    org_id          uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id       uuid NOT NULL DEFAULT gen_random_uuid(),
    kind            text NOT NULL,
    connector       text NOT NULL DEFAULT 'generic_webhook',
    config          jsonb NOT NULL DEFAULT '{}'::jsonb,
    credentials_ct  bytea,
    status          text NOT NULL DEFAULT 'active',
    last_delivery_at timestamptz,
    last_test       jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, system_id)
);
ALTER TABLE consentvault.connected_system
    ADD COLUMN IF NOT EXISTS name               text,
    ADD COLUMN IF NOT EXISTS endpoint           text,
    ADD COLUMN IF NOT EXISTS signature          text,
    ADD COLUMN IF NOT EXISTS contact_form       text,
    ADD COLUMN IF NOT EXISTS retry_window_hours integer,
    ADD COLUMN IF NOT EXISTS public_key         text,
    ADD COLUMN IF NOT EXISTS created_by         uuid;
ALTER TABLE consentvault.connected_system
    ADD CONSTRAINT connected_system_kind_admin CHECK (kind IN ('crm', 'dialer', 'sms', 'email', 'ai_agent', 'webhook')),
    ADD CONSTRAINT connected_system_status_admin CHECK (status IN ('active', 'paused')),
    ADD CONSTRAINT connected_system_endpoint_https CHECK (endpoint IS NULL OR endpoint ~ '^https://'),
    ADD CONSTRAINT connected_system_signature_admin CHECK (signature IS NULL OR signature IN ('ed25519', 'hmac')),
    ADD CONSTRAINT connected_system_contact_form_admin CHECK (contact_form IS NULL OR contact_form IN ('plaintext', 'fingerprint')),
    ADD CONSTRAINT connected_system_retry_admin CHECK (retry_window_hours IS NULL OR retry_window_hours BETWEEN 1 AND 168);
CREATE UNIQUE INDEX connected_system_org_name_idx ON consentvault.connected_system (org_id, lower(name)) WHERE name IS NOT NULL;

-- Evidence export jobs (written by the admin plane, read and advanced by the evidence-export lane) ------------------
CREATE TABLE consentvault.export_job (
    org_id             uuid NOT NULL REFERENCES consentvault.organization (org_id),
    export_id          uuid NOT NULL DEFAULT gen_random_uuid(),
    contact_fp         text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    status             text NOT NULL DEFAULT 'building' CHECK (status IN ('building', 'ready', 'failed')),
    progress_done      integer NOT NULL DEFAULT 0 CHECK (progress_done >= 0),
    progress_total     integer CHECK (progress_total IS NULL OR progress_total >= 0),
    failed_cause       text CHECK (failed_cause IS NULL OR failed_cause ~ '^[A-Za-z][A-Za-z0-9_]{0,63}$'),
    requested_by       uuid NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    completed_at       timestamptz,
    package_object_key text,
    package_sha256     text CHECK (package_sha256 IS NULL OR package_sha256 ~ '^[0-9a-f]{64}$'),
    signature          text,
    expires_at         timestamptz,
    downloaded_at      timestamptz,
    PRIMARY KEY (org_id, export_id),
    CONSTRAINT export_job_ready_shape CHECK (status <> 'ready' OR (package_object_key IS NOT NULL AND package_sha256 IS NOT NULL
                                                                  AND completed_at IS NOT NULL)),
    CONSTRAINT export_job_failed_shape CHECK ((status = 'failed') = (failed_cause IS NOT NULL))
);
CREATE FUNCTION consentvault.export_job_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.export_job is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.org_id, NEW.export_id, NEW.contact_fp, NEW.requested_by, NEW.created_at)
       IS DISTINCT FROM (OLD.org_id, OLD.export_id, OLD.contact_fp, OLD.requested_by, OLD.created_at) THEN
        RAISE EXCEPTION 'consentvault.export_job: only status and progress columns change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER export_job_guard BEFORE UPDATE OR DELETE ON consentvault.export_job
    FOR EACH ROW EXECUTE FUNCTION consentvault.export_job_guard();

-- Audit: one chain per organisation and one platform chain ---------------------------------------------------------
-- org_id is NULL for the platform chain. Rows are written only by append_audit / append_platform_audit, which hold
-- the chain's lock, read the head and compute the row hash; a trigger refuses a fork or a gap even from the owner.
CREATE TABLE consentvault.audit_event (
    audit_id    uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id      uuid REFERENCES consentvault.organization (org_id),
    chain_key   uuid GENERATED ALWAYS AS (coalesce(org_id, '00000000-0000-0000-0000-000000000000'::uuid)) STORED,
    seq         bigint NOT NULL CHECK (seq >= 1),
    actor_kind  text NOT NULL CHECK (actor_kind IN ('member', 'credential', 'operator', 'system')),
    actor_id    text CHECK (actor_id IS NULL OR length(actor_id) BETWEEN 1 AND 200),
    action      text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.:]{2,63}$'),
    target_kind text NOT NULL CHECK (target_kind ~ '^[a-z][a-z0-9_]{0,31}$'),
    target_id   text CHECK (target_id IS NULL OR length(target_id) BETWEEN 1 AND 200),
    reason      text CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 500),
    request_id  text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 100),
    ip_ct       bytea,
    at          timestamptz NOT NULL,
    prev_hash   text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    row_hash    text NOT NULL CHECK (row_hash ~ '^[0-9a-f]{64}$'),
    UNIQUE (chain_key, seq),
    UNIQUE (chain_key, row_hash)
);
CREATE INDEX audit_event_org_at_idx ON consentvault.audit_event (org_id, at DESC, audit_id DESC);
CREATE TRIGGER audit_event_append_only BEFORE UPDATE OR DELETE ON consentvault.audit_event
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER audit_event_no_truncate BEFORE TRUNCATE ON consentvault.audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

CREATE FUNCTION consentvault.audit_row_hash(p_prev text, p_org uuid, p_seq bigint, p_actor_kind text, p_actor_id text,
        p_action text, p_target_kind text, p_target_id text, p_reason text, p_request_id text, p_at timestamptz)
    RETURNS text LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT encode(sha256(convert_to(concat_ws(E'\x1f', 'audit.v1', p_prev, coalesce(p_org::text, 'platform'), p_seq::text,
        p_actor_kind, coalesce(p_actor_id, ''), p_action, p_target_kind, coalesce(p_target_id, ''),
        coalesce(p_reason, ''), p_request_id, ((extract(epoch FROM p_at) * 1000000)::bigint)::text), 'UTF8')), 'hex');
$$;
GRANT EXECUTE ON FUNCTION consentvault.audit_row_hash(text, uuid, bigint, text, text, text, text, text, text, text, timestamptz)
    TO consentvault_app, consentvault_worker;

CREATE FUNCTION consentvault.audit_chain_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    h record;
    ck uuid := coalesce(NEW.org_id, '00000000-0000-0000-0000-000000000000'::uuid);  -- generated columns are not yet set in a BEFORE trigger
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('consentvault.audit:' || ck::text));
    SELECT seq, row_hash INTO h FROM consentvault.audit_event
     WHERE chain_key OPERATOR(pg_catalog.=) ck ORDER BY seq DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.seq OPERATOR(pg_catalog.<>) 1 OR NEW.prev_hash OPERATOR(pg_catalog.<>) repeat('0', 64) THEN
            RAISE EXCEPTION 'consentvault audit: the first row of a chain is seq 1 on the zero hash' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF NEW.seq OPERATOR(pg_catalog.<>) h.seq + 1 OR NEW.prev_hash OPERATOR(pg_catalog.<>) h.row_hash THEN
        RAISE EXCEPTION 'consentvault audit: a row must extend the head of its chain (fork or gap refused)' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.row_hash OPERATOR(pg_catalog.<>) consentvault.audit_row_hash(NEW.prev_hash, NEW.org_id, NEW.seq, NEW.actor_kind,
            NEW.actor_id, NEW.action, NEW.target_kind, NEW.target_id, NEW.reason, NEW.request_id, NEW.at) THEN
        RAISE EXCEPTION 'consentvault audit: row_hash does not match the row' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER audit_event_chain BEFORE INSERT ON consentvault.audit_event
    FOR EACH ROW EXECUTE FUNCTION consentvault.audit_chain_guard();

-- Owner-rights functions (owned by consentvault_operator below) ----------------------------------------------------
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
GRANT EXECUTE ON FUNCTION consentvault.current_org() TO consentvault_operator;
GRANT SELECT, INSERT ON consentvault.audit_event TO consentvault_operator;
GRANT SELECT (org_id, invite_id, token_digest, email_norm, role, invited_by, invited_by_operator, expires_at,
              accepted_at, withdrawn_at) ON consentvault.invite TO consentvault_operator;
GRANT SELECT (org_id, member_id, idp_issuer, idp_subject, role) ON consentvault.member TO consentvault_operator;
GRANT SELECT (org_id, event_id, received_at, seq, source_id) ON consentvault.event TO consentvault_operator;
GRANT SELECT (org_id, event_id) ON consentvault.seal TO consentvault_operator;

-- Pre-tenant: what an invitation is for, found by the digest of its token. One row at most; never the token. It reads
-- no organisation name and no person's name (the operator role reads neither); the caller enters the invitation's own
-- organisation with a short token to read those.
CREATE FUNCTION consentvault.invite_lookup(p_token_digest text)
    RETURNS TABLE (org_id uuid, invite_id uuid, org_status text, role text, invited_by uuid, invited_by_operator text,
                   email_norm text, expires_at timestamptz, accepted_at timestamptz, withdrawn_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT i.org_id, i.invite_id, o.status, i.role, i.invited_by, i.invited_by_operator, i.email_norm, i.expires_at,
           i.accepted_at, i.withdrawn_at
    FROM consentvault.invite i
    JOIN consentvault.organization o ON o.org_id = i.org_id
    WHERE p_token_digest ~ '^[0-9a-f]{64}$' AND i.token_digest = p_token_digest;
$$;
ALTER FUNCTION consentvault.invite_lookup(text) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.invite_lookup(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.invite_lookup(text) TO consentvault_app;

-- Pre-tenant: every organisation one signed-in identity belongs to, whatever its status. Auto-join does not exist:
-- a membership is only ever a row an invitation accepted.
CREATE FUNCTION consentvault.session_memberships(p_idp_issuer text, p_idp_subject text)
    RETURNS TABLE (org_id uuid, member_id uuid, role text, status text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT m.org_id, m.member_id, m.role, o.status
    FROM consentvault.member m
    JOIN consentvault.organization o ON o.org_id = m.org_id
    WHERE m.idp_issuer = p_idp_issuer AND m.idp_subject = p_idp_subject
    ORDER BY m.org_id;
$$;
ALTER FUNCTION consentvault.session_memberships(text, text) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.session_memberships(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.session_memberships(text, text) TO consentvault_app;

-- Tenant: append one audit row to the current organisation's chain. Takes no organisation argument.
CREATE FUNCTION consentvault.append_audit(p_actor_kind text, p_actor_id text, p_action text, p_target_kind text,
        p_target_id text, p_reason text, p_request_id text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org  uuid := (SELECT consentvault.current_org());
    h    record;
    nseq bigint;
    prev text;
    stamp timestamptz := clock_timestamp();
    rh   text;
    id   uuid := gen_random_uuid();
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault audit: an audit row needs an entered tenant' USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('consentvault.audit:' || org::text));
    SELECT a.seq, a.row_hash INTO h FROM consentvault.audit_event a WHERE a.org_id = org ORDER BY a.seq DESC LIMIT 1;
    IF FOUND THEN nseq := h.seq + 1; prev := h.row_hash; ELSE nseq := 1; prev := repeat('0', 64); END IF;
    rh := consentvault.audit_row_hash(prev, org, nseq, p_actor_kind, p_actor_id, p_action, p_target_kind, p_target_id,
                                      p_reason, p_request_id, stamp);
    INSERT INTO consentvault.audit_event (audit_id, org_id, seq, actor_kind, actor_id, action, target_kind, target_id,
                                          reason, request_id, at, prev_hash, row_hash)
    VALUES (id, org, nseq, p_actor_kind, p_actor_id, p_action, p_target_kind, p_target_id, p_reason, p_request_id,
            stamp, prev, rh);
    RETURN id;
END;
$$;
ALTER FUNCTION consentvault.append_audit(text, text, text, text, text, text, text) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.append_audit(text, text, text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.append_audit(text, text, text, text, text, text, text) TO consentvault_app;

-- Platform chain (operator actions on the platform itself): callable only by the schema owner's operator console.
CREATE FUNCTION consentvault.append_platform_audit(p_actor_id text, p_action text, p_target_kind text,
        p_target_id text, p_reason text, p_request_id text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    h    record;
    nseq bigint;
    prev text;
    stamp timestamptz := clock_timestamp();
    rh   text;
    id   uuid := gen_random_uuid();
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('consentvault.audit:00000000-0000-0000-0000-000000000000'));
    SELECT a.seq, a.row_hash INTO h FROM consentvault.audit_event a WHERE a.org_id IS NULL ORDER BY a.seq DESC LIMIT 1;
    IF FOUND THEN nseq := h.seq + 1; prev := h.row_hash; ELSE nseq := 1; prev := repeat('0', 64); END IF;
    rh := consentvault.audit_row_hash(prev, NULL, nseq, 'operator', p_actor_id, p_action, p_target_kind, p_target_id,
                                      p_reason, p_request_id, stamp);
    INSERT INTO consentvault.audit_event (audit_id, org_id, seq, actor_kind, actor_id, action, target_kind, target_id,
                                          reason, request_id, at, prev_hash, row_hash)
    VALUES (id, NULL, nseq, 'operator', p_actor_id, p_action, p_target_kind, p_target_id, p_reason, p_request_id,
            stamp, prev, rh);
    RETURN id;
END;
$$;
ALTER FUNCTION consentvault.append_platform_audit(text, text, text, text, text, text) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.append_platform_audit(text, text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.append_platform_audit(text, text, text, text, text, text) TO CURRENT_USER;

-- Chain heads, for the anchor job: the current organisation's, and the platform's (owner console only).
CREATE FUNCTION consentvault.audit_head() RETURNS TABLE (seq bigint, row_hash text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT a.seq, a.row_hash FROM consentvault.audit_event a
     WHERE a.org_id = (SELECT consentvault.current_org()) ORDER BY a.seq DESC LIMIT 1;
$$;
ALTER FUNCTION consentvault.audit_head() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.audit_head() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.audit_head() TO consentvault_app, consentvault_worker;

CREATE FUNCTION consentvault.platform_audit_head() RETURNS TABLE (seq bigint, row_hash text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT a.seq, a.row_hash FROM consentvault.audit_event a WHERE a.org_id IS NULL ORDER BY a.seq DESC LIMIT 1;
$$;
ALTER FUNCTION consentvault.platform_audit_head() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.platform_audit_head() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.platform_audit_head() TO CURRENT_USER;

-- Chain verification: rows of the current organisation only (security_invoker); the platform view is the operator's.
CREATE VIEW consentvault.audit_chain_breaks WITH (security_invoker = true) AS
SELECT org_id, seq, audit_id,
       CASE WHEN expected_seq <> seq THEN 'seq_gap'
            WHEN expected_prev <> prev_hash THEN 'prev_hash_mismatch'
            ELSE 'row_hash_mismatch' END AS reason
FROM (
    SELECT a.org_id, a.seq, a.audit_id, a.prev_hash,
           coalesce(lag(a.seq) OVER w + 1, 1) AS expected_seq,
           coalesce(lag(a.row_hash) OVER w, repeat('0', 64)) AS expected_prev,
           a.row_hash,
           consentvault.audit_row_hash(a.prev_hash, a.org_id, a.seq, a.actor_kind, a.actor_id, a.action, a.target_kind,
                                       a.target_id, a.reason, a.request_id, a.at) AS recomputed
    FROM consentvault.audit_event a
    WINDOW w AS (PARTITION BY a.chain_key ORDER BY a.seq)
) t
WHERE expected_seq <> seq OR expected_prev <> prev_hash OR recomputed <> row_hash;

-- Counts for the overview. No personal data; the current organisation only. A developer token cannot read events, so
-- the counts come through here.
CREATE FUNCTION consentvault.health_counts()
    RETURNS TABLE (unsealed_over_1h bigint, first_event_at timestamptz, first_event_sealed boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT (SELECT count(*) FROM consentvault.event e
             WHERE e.org_id = (SELECT consentvault.current_org()) AND e.received_at < clock_timestamp() - interval '1 hour'
               AND NOT EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.org_id = e.org_id AND s.event_id = e.event_id)),
           f.received_at,
           CASE WHEN f.event_id IS NULL THEN NULL
                ELSE EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.org_id = f.org_id AND s.event_id = f.event_id) END
    FROM (SELECT 1) one
    LEFT JOIN LATERAL (SELECT e.org_id, e.event_id, e.received_at FROM consentvault.event e
                        WHERE e.org_id = (SELECT consentvault.current_org()) ORDER BY e.seq LIMIT 1) f ON true;
$$;
ALTER FUNCTION consentvault.health_counts() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.health_counts() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.health_counts() TO consentvault_app;

-- The latest event per capture source of the current organisation: when, which sequence number, whether sealed. No
-- personal field. A developer token cannot read events, so the source list reads this instead.
CREATE FUNCTION consentvault.source_last_events()
    RETURNS TABLE (source_id uuid, last_event_at timestamptz, last_event_seq bigint, last_event_sealed boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT DISTINCT ON (e.source_id) e.source_id, e.received_at, e.seq,
           EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.org_id = e.org_id AND s.event_id = e.event_id)
    FROM consentvault.event e
    WHERE e.org_id = (SELECT consentvault.current_org()) AND e.source_id IS NOT NULL
    ORDER BY e.source_id, e.seq DESC;
$$;
ALTER FUNCTION consentvault.source_last_events() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.source_last_events() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.source_last_events() TO consentvault_app;

REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;

-- The claims of the token this transaction entered (org, scopes, credential id); no row when there is none.
CREATE FUNCTION consentvault.current_token_claims() RETURNS TABLE (org_id uuid, scopes text[], credential_id text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT v.org_id, v.scopes, v.credential_id
    FROM consentvault.verify_org_token(nullif(pg_catalog.current_setting('consentvault.org_token', true), '')) v;
$$;
REVOKE ALL ON FUNCTION consentvault.current_token_claims() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.current_token_claims() TO consentvault_app, consentvault_worker;

CREATE FUNCTION consentvault.may_read_audit() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.audit_event'::regclass)
        OR coalesce(current_setting('consentvault.org_token', true), '') = ''
        OR coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'audit_read'], false);
$$;
REVOKE ALL ON FUNCTION consentvault.may_read_audit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.may_read_audit() TO consentvault_app, consentvault_worker;

-- Row-level security on every new tenant table -----------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['org_fingerprint_secret', 'channel', 'purpose', 'invite', 'policy', 'policy_approval',
                             'policy_attestation', 'doc_checklist', 'retention_policy', 'connected_system', 'export_job',
                             'audit_event'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
    END LOOP;
END
$$;
CREATE POLICY audit_event_read_scope ON consentvault.audit_event AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_audit()));
CREATE POLICY export_job_read_scope ON consentvault.export_job AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_evidence()));

-- Grants to the runtime role ----------------------------------------------------------------------------------------
GRANT SELECT ON consentvault.channel, consentvault.purpose, consentvault.policy, consentvault.policy_approval,
    consentvault.policy_attestation, consentvault.doc_checklist, consentvault.retention_policy, consentvault.export_job,
    consentvault.audit_event, consentvault.attestation_text, consentvault.rule_reference TO consentvault_app;
GRANT SELECT ON consentvault.audit_chain_breaks TO consentvault_app;
GRANT SELECT (org_id, invite_id, email_norm, role, invited_by, invited_by_operator, created_at, expires_at, accepted_at,
              accepted_member_id, withdrawn_at) ON consentvault.invite TO consentvault_app;
GRANT INSERT ON consentvault.invite TO consentvault_app;
GRANT UPDATE (accepted_at, accepted_member_id, withdrawn_at) ON consentvault.invite TO consentvault_app;
GRANT INSERT, DELETE ON consentvault.member TO consentvault_app;
GRANT UPDATE (role, display_name, last_sign_in_at) ON consentvault.member TO consentvault_app;
GRANT INSERT ON consentvault.brand TO consentvault_app;
GRANT INSERT ON consentvault.capture_source TO consentvault_app;
GRANT UPDATE (name, brand_ids, allowed_origins, status, retired_at) ON consentvault.capture_source TO consentvault_app;
GRANT SELECT (name, created_by, last_used_at, revoked_by, revoke_reason, site_key_id) ON consentvault.credential TO consentvault_app;
GRANT INSERT ON consentvault.credential TO consentvault_app;
GRANT UPDATE (revoked_at, revoked_by, revoke_reason, last_used_at) ON consentvault.credential TO consentvault_app;
GRANT INSERT ON consentvault.policy TO consentvault_app;
GRANT UPDATE (rules, status, approved_by, approved_at, retired_at, retired_by_version) ON consentvault.policy TO consentvault_app;
GRANT INSERT ON consentvault.policy_approval, consentvault.policy_attestation, consentvault.retention_policy TO consentvault_app;
GRANT INSERT ON consentvault.doc_checklist TO consentvault_app;
GRANT UPDATE (label, elements, status, approved_by, approved_at) ON consentvault.doc_checklist TO consentvault_app;
GRANT SELECT (org_id, system_id, kind, connector, config, status, created_at, name, endpoint, signature, contact_form,
              retry_window_hours, public_key, created_by, last_delivery_at, last_test) ON consentvault.connected_system TO consentvault_app;
GRANT INSERT ON consentvault.connected_system TO consentvault_app;
GRANT UPDATE (name, endpoint, contact_form, retry_window_hours, status) ON consentvault.connected_system TO consentvault_app;
GRANT INSERT ON consentvault.export_job TO consentvault_app;
GRANT UPDATE (status, progress_done, progress_total, failed_cause, completed_at, package_object_key, package_sha256,
              signature, expires_at, downloaded_at) ON consentvault.export_job TO consentvault_app;
