-- Reverses 0015_hardening.sql: the checklist results and the site-key hash lookup go.
-- Run it as a superuser (or a BYPASSRLS role), in one transaction. Refused while any checklist result exists.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regprocedure('consentvault.resolve_site_key(text)') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0015 refused: 0015 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.doc_check_result) THEN
        RAISE EXCEPTION 'consentvault down 0015 refused: checklist results are stored; they are records and are not dropped';
    END IF;
END
$$;

REVOKE SELECT (org_id, version, status) ON consentvault.doc_checklist FROM consentvault_operator;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM consentvault.legal_hold WHERE reason LIKE 'ocv1:%' OR release_reason LIKE 'ocv1:%') THEN
        RAISE EXCEPTION 'consentvault down 0015 refused: hold reasons are sealed under the organization key; they are records and are not shortened';
    END IF;
END
$$;
ALTER TABLE consentvault.legal_hold DROP CONSTRAINT legal_hold_reason_check;
ALTER TABLE consentvault.legal_hold ADD CONSTRAINT legal_hold_reason_check CHECK (length(reason) BETWEEN 1 AND 500);
ALTER TABLE consentvault.legal_hold DROP CONSTRAINT legal_hold_release_reason_check;
ALTER TABLE consentvault.legal_hold ADD CONSTRAINT legal_hold_release_reason_check
    CHECK (release_reason IS NULL OR length(release_reason) BETWEEN 1 AND 500);
DROP FUNCTION consentvault.record_doc_check(uuid, integer, text[], text[], uuid);
DROP TABLE consentvault.doc_check_result;
DROP FUNCTION consentvault.resolve_site_key(text);
REVOKE SELECT (org_id, source_id, brand_ids, allowed_origins, status) ON consentvault.capture_source FROM consentvault_operator;
GRANT SELECT (org_id, source_id, allowed_origins) ON consentvault.capture_source TO consentvault_operator;
REVOKE SELECT (site_key_hash) ON consentvault.credential FROM consentvault_operator;
ALTER TABLE consentvault.credential DROP CONSTRAINT credential_site_key_hash_shape;
ALTER TABLE consentvault.credential DROP COLUMN site_key_hash;

COMMIT;
