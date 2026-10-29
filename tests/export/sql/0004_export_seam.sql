-- Test seam for the evidence export lane. The real export_job table and append_audit function ship in the admin lane's
-- migration; this file restates them exactly as that migration defines them (columns, checks, guard, policies, grants)
-- so the export tests run on a pinned chain (core, tenancy, replay guard) that other lanes' unfinished migrations
-- cannot break. tests/export/test_seam_conformance.py compares this definition to the real chain whenever it applies.
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
ALTER TABLE consentvault.export_job ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.export_job FORCE ROW LEVEL SECURITY;
CREATE POLICY export_job_tenant ON consentvault.export_job USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
CREATE POLICY export_job_read_scope ON consentvault.export_job AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_evidence()));
GRANT SELECT ON consentvault.export_job TO consentvault_app;
GRANT INSERT ON consentvault.export_job TO consentvault_app;
GRANT UPDATE (status, progress_done, progress_total, failed_cause, completed_at, package_object_key, package_sha256,
              signature, expires_at, downloaded_at) ON consentvault.export_job TO consentvault_app;

-- Simplified audit sink with the real function's signature: (actor kind, actor id, action, target kind, target id,
-- reason, request id) -> audit id, written for the entered tenant.
CREATE TABLE consentvault.audit_event (
    audit_id    uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES consentvault.organization (org_id),
    actor_kind  text NOT NULL CHECK (actor_kind IN ('member', 'credential', 'operator', 'system')),
    actor_id    text CHECK (actor_id IS NULL OR length(actor_id) BETWEEN 1 AND 200),
    action      text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.:]{2,63}$'),
    target_kind text NOT NULL CHECK (target_kind ~ '^[a-z][a-z0-9_]{0,31}$'),
    target_id   text,
    reason      text,
    request_id  text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 100),
    at          timestamptz NOT NULL
);
ALTER TABLE consentvault.audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.audit_event FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_tenant ON consentvault.audit_event USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
CREATE FUNCTION consentvault.append_audit(p_actor_kind text, p_actor_id text, p_action text, p_target_kind text,
        p_target_id text, p_reason text, p_request_id text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := (SELECT consentvault.current_org());
    id  uuid := gen_random_uuid();
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault audit: an audit row needs an entered tenant' USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    INSERT INTO consentvault.audit_event (audit_id, org_id, actor_kind, actor_id, action, target_kind, target_id, reason,
                                          request_id, at)
    VALUES (id, org, p_actor_kind, p_actor_id, p_action, p_target_kind, p_target_id, p_reason, p_request_id, clock_timestamp());
    RETURN id;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.append_audit(text, text, text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.append_audit(text, text, text, text, text, text, text) TO consentvault_app;
