-- Hardening after the second adversarial review.
--
-- 1. Site keys by hash. A browser capture forwarded by the edge names only a site key. The vault finds the organisation
--    and the capture source from the key's SHA-256, stored on the site-key credential (one credential per capture source
--    and key). The lookup is the one pre-authentication cross-organisation read for the edge path, one key at a time,
--    like resolve_credential: it answers one row or none and never lists.
-- 2. Per-record checklist results. A policy that names a checklist answers from the stored result for the record, and
--    says "not checked" for a record nobody has checked, instead of "unavailable". Documentation completeness only.
--
-- No column is added to seal, chain_head, contact_log or review. Every column the new functions read through the
-- operator role is granted to it explicitly below.

-- 1. Site keys ---------------------------------------------------------------------------------------------------------
ALTER TABLE consentvault.credential
    ADD COLUMN site_key_hash text UNIQUE CHECK (site_key_hash IS NULL OR site_key_hash ~ '^[0-9a-f]{64}$');
UPDATE consentvault.credential
   SET site_key_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(site_key_id, 'UTF8')), 'hex')
 WHERE site_key_id IS NOT NULL AND site_key_hash IS NULL;
ALTER TABLE consentvault.credential ADD CONSTRAINT credential_site_key_hash_shape
    CHECK ((kind = 'edge_site_key') = (site_key_hash IS NOT NULL));
GRANT SELECT (site_key_hash) ON consentvault.credential TO consentvault_operator;
GRANT SELECT (org_id, source_id, brand_ids, allowed_origins, status) ON consentvault.capture_source TO consentvault_operator;

GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;

CREATE FUNCTION consentvault.resolve_site_key(p_site_key text)
    RETURNS TABLE (org_id uuid, credential_id uuid, source_id uuid, brand_ids uuid[], allowed_origins text[], state text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT c.org_id, c.credential_id, c.source_id, s.brand_ids, s.allowed_origins,
           CASE WHEN c.revoked_at IS NOT NULL THEN 'revoked'
                WHEN s.status <> 'active' THEN 'source_retired'
                ELSE 'active' END
    FROM consentvault.credential c
    JOIN consentvault.capture_source s ON s.org_id = c.org_id AND s.source_id = c.source_id
    WHERE p_site_key ~ '^cv_site_[A-Za-z0-9_-]{16,64}$'
      AND c.site_key_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_site_key, 'UTF8')), 'hex');
$$;
ALTER FUNCTION consentvault.resolve_site_key(text) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.resolve_site_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.resolve_site_key(text) TO consentvault_app;

-- 2. Checklist results -------------------------------------------------------------------------------------------------
-- One row per check of one record against one approved checklist version. A re-check is a new row; readers take the
-- latest. Append-only. No foreign key to the event: erasure and offboarding may remove an event's personal data, and a
-- result row names only ids.
CREATE TABLE consentvault.doc_check_result (
    org_id            uuid NOT NULL REFERENCES consentvault.organization (org_id),
    check_id          uuid NOT NULL DEFAULT gen_random_uuid(),
    event_id          uuid NOT NULL,
    checklist_version integer NOT NULL CHECK (checklist_version >= 1),
    present           text[] NOT NULL DEFAULT '{}',
    missing           text[] NOT NULL DEFAULT '{}',
    checked_by        uuid,
    checked_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, check_id),
    FOREIGN KEY (org_id, checklist_version) REFERENCES consentvault.doc_checklist (org_id, version),
    CONSTRAINT doc_check_result_disjoint CHECK (NOT (present && missing))
);
CREATE INDEX doc_check_result_event_idx ON consentvault.doc_check_result (org_id, event_id, checklist_version, checked_at DESC);
CREATE TRIGGER doc_check_result_append_only BEFORE UPDATE OR DELETE ON consentvault.doc_check_result
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER doc_check_result_no_truncate BEFORE TRUNCATE ON consentvault.doc_check_result
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();
ALTER TABLE consentvault.doc_check_result ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.doc_check_result FORCE ROW LEVEL SECURITY;
CREATE POLICY doc_check_result_tenant ON consentvault.doc_check_result
    USING (org_id = (SELECT consentvault.current_org())) WITH CHECK (org_id = (SELECT consentvault.current_org()));
REVOKE ALL ON consentvault.doc_check_result FROM PUBLIC;
GRANT SELECT ON consentvault.doc_check_result TO consentvault_app;
GRANT INSERT, SELECT (org_id, check_id) ON consentvault.doc_check_result TO consentvault_operator;  -- RETURNING needs the read
GRANT SELECT (org_id, version, status) ON consentvault.doc_checklist TO consentvault_operator;

-- The only writer: an approved checklist version and a record of this organisation. It runs as the operator role (a
-- tenant token with admin scope cannot read events) and filters on current_org() itself.
CREATE FUNCTION consentvault.record_doc_check(p_event_id uuid, p_version integer, p_present text[], p_missing text[],
                                              p_checked_by uuid) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := (SELECT consentvault.current_org());
    id  uuid;
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault doc check: no organisation entered' USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM consentvault.doc_checklist c
                    WHERE c.org_id = org AND c.version = p_version AND c.status = 'approved') THEN
        RAISE EXCEPTION 'consentvault doc check: checklist version % is not an approved version of this organisation', p_version
            USING ERRCODE = 'no_data_found';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM consentvault.event e WHERE e.org_id = org AND e.event_id = p_event_id) THEN
        RAISE EXCEPTION 'consentvault doc check: no such record in this organisation' USING ERRCODE = 'no_data_found';
    END IF;
    INSERT INTO consentvault.doc_check_result (org_id, event_id, checklist_version, present, missing, checked_by)
    VALUES (org, p_event_id, p_version, coalesce(p_present, '{}'), coalesce(p_missing, '{}'), p_checked_by)
    RETURNING check_id INTO id;
    RETURN id;
END;
$$;
ALTER FUNCTION consentvault.record_doc_check(uuid, integer, text[], text[], uuid) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.record_doc_check(uuid, integer, text[], text[], uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.record_doc_check(uuid, integer, text[], text[], uuid) TO consentvault_app;

REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;

-- 3. Hold reasons are sealed under the organisation key (holds.seal_reason): the ciphertext envelope is longer than the
--    500 plain characters it carries, so the two length limits widen. The rest of the guard is unchanged.
ALTER TABLE consentvault.legal_hold DROP CONSTRAINT legal_hold_reason_check;
ALTER TABLE consentvault.legal_hold ADD CONSTRAINT legal_hold_reason_check CHECK (length(reason) BETWEEN 1 AND 4000);
ALTER TABLE consentvault.legal_hold DROP CONSTRAINT legal_hold_release_reason_check;
ALTER TABLE consentvault.legal_hold ADD CONSTRAINT legal_hold_release_reason_check
    CHECK (release_reason IS NULL OR length(release_reason) BETWEEN 1 AND 4000);
