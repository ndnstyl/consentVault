-- Records list exports, the request half (records.md section 7): one row per requested file, what was asked for, who asked and
-- where it stands. The file itself is built, kept and served by the export worker; this table is the job record the portal lists.
-- At most one export of an organization is building at a time (export_in_progress). A row holds the filters and the form of the
-- contact point asked for, never a contact point, a name or a company.
CREATE TABLE consentvault.record_export (
    org_id         uuid NOT NULL REFERENCES consentvault.organization (org_id),
    export_id      uuid NOT NULL DEFAULT gen_random_uuid(),
    status         text NOT NULL DEFAULT 'building' CHECK (status IN ('building', 'ready', 'failed', 'expired')),
    contact_form   text NOT NULL CHECK (contact_form IN ('masked', 'full', 'fingerprint')),
    include_person boolean NOT NULL,
    filters        jsonb NOT NULL DEFAULT '{}'::jsonb,
    reason         text CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 200),
    requested_by   text NOT NULL CHECK (length(requested_by) BETWEEN 1 AND 200),
    created_at     timestamptz NOT NULL,
    row_estimate   bigint CHECK (row_estimate IS NULL OR row_estimate >= 0),
    row_count      bigint CHECK (row_count IS NULL OR row_count >= 0),
    progress_done  bigint NOT NULL DEFAULT 0 CHECK (progress_done >= 0),
    completed_at   timestamptz,
    expires_at     timestamptz,
    downloaded_at  timestamptz,
    sha256         text CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    failed_cause   text CHECK (failed_cause IS NULL OR length(failed_cause) BETWEEN 1 AND 100),
    PRIMARY KEY (org_id, export_id),
    CONSTRAINT record_export_full_has_reason CHECK (contact_form <> 'full' OR reason IS NOT NULL),
    CONSTRAINT record_export_fingerprint_has_no_person CHECK (contact_form <> 'fingerprint' OR NOT include_person)
);
CREATE UNIQUE INDEX record_export_one_building_idx ON consentvault.record_export (org_id) WHERE status = 'building';
CREATE INDEX record_export_org_created_idx ON consentvault.record_export (org_id, created_at DESC, export_id DESC);
ALTER TABLE consentvault.record_export ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.record_export FORCE ROW LEVEL SECURITY;
CREATE POLICY record_export_tenant ON consentvault.record_export USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
-- A list export row holds the reason an admin gave and who asked: an admin or a viewer reads it, a developer does not.
CREATE FUNCTION consentvault.may_read_record_exports() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.record_export'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'proof_read', 'records_read'], false);
$$;
REVOKE ALL ON FUNCTION consentvault.may_read_record_exports() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.may_read_record_exports() TO consentvault_app, consentvault_console;
CREATE POLICY record_export_read_scope ON consentvault.record_export AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_record_exports()));
REVOKE ALL ON consentvault.record_export FROM PUBLIC;
GRANT SELECT, INSERT ON consentvault.record_export TO consentvault_app;
GRANT UPDATE (status, row_count, progress_done, completed_at, expires_at, downloaded_at, sha256, failed_cause)
    ON consentvault.record_export TO consentvault_app;
GRANT SELECT, INSERT, UPDATE ON consentvault.record_export TO consentvault_console;

-- One-use download links (records.md section 7): a link is good for 15 minutes from the moment it is minted and for one
-- download. The link token carries the ids and a signature; this row says whether it was used and who minted it.
CREATE TABLE consentvault.record_export_link (
    org_id     uuid NOT NULL,
    link_id    uuid NOT NULL DEFAULT gen_random_uuid(),
    export_id  uuid NOT NULL,
    minted_by  text NOT NULL CHECK (length(minted_by) BETWEEN 1 AND 200),
    minted_at  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    PRIMARY KEY (org_id, link_id),
    FOREIGN KEY (org_id, export_id) REFERENCES consentvault.record_export (org_id, export_id)
);
CREATE INDEX record_export_link_export_idx ON consentvault.record_export_link (org_id, export_id, minted_at DESC);
ALTER TABLE consentvault.record_export_link ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.record_export_link FORCE ROW LEVEL SECURITY;
CREATE POLICY record_export_link_tenant ON consentvault.record_export_link USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
CREATE POLICY record_export_link_read_scope ON consentvault.record_export_link AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_record_exports()));
REVOKE ALL ON consentvault.record_export_link FROM PUBLIC;
GRANT SELECT, INSERT ON consentvault.record_export_link TO consentvault_app;
GRANT UPDATE (used_at) ON consentvault.record_export_link TO consentvault_app;
