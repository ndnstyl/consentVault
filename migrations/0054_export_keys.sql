-- A records list export is sealed under a data key of its own, so it can be destroyed without deleting the stored file (the evidence
-- bucket keeps objects under compliance retention, so deletion cannot be counted on): destroy the key and the file is noise.
--
-- * record_export_key: one 256-bit data key per export, wrapped by the organization key. It is destroyed (wrapped set to null,
--   destroyed_at set) when the 24 hours are up, and when an erasure touches a record the export holds. object_state says what
--   became of the stored file: 'deleted', 'retained' (the store keeps objects until retention ends) or 'delete_failed'; null
--   until the worker has tried.
-- * record_export_record: which records each export holds, written in the same transaction that reads them.
-- * record_export_link.revoked_at: an erasure revokes every link of an export it destroys.
-- * erase_contact (body of 0052 plus the block marked below): in the erasure's transaction, every export that holds a record of the
--   erased contact point is marked expired, its links are revoked and its key is destroyed. An export builder takes the same lock
--   (records_export_shred:<org>) for its whole read, so a build either sees the record erased or is recorded here before the erasure.
CREATE TABLE consentvault.record_export_key (
    org_id       uuid NOT NULL,
    export_id    uuid NOT NULL,
    wrapped      bytea CHECK (wrapped IS NULL OR octet_length(wrapped) > 0),
    key_version  integer NOT NULL CHECK (key_version >= 1),
    created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    destroyed_at timestamptz,
    object_state text CHECK (object_state IN ('deleted', 'retained', 'delete_failed')),
    PRIMARY KEY (org_id, export_id),
    FOREIGN KEY (org_id, export_id) REFERENCES consentvault.record_export (org_id, export_id),
    CONSTRAINT record_export_key_shape CHECK ((wrapped IS NULL) = (destroyed_at IS NOT NULL))
);
CREATE TABLE consentvault.record_export_record (
    org_id    uuid NOT NULL,
    export_id uuid NOT NULL,
    record_id uuid NOT NULL,
    PRIMARY KEY (org_id, export_id, record_id),
    FOREIGN KEY (org_id, export_id) REFERENCES consentvault.record_export (org_id, export_id)
);
CREATE INDEX record_export_record_by_record_idx ON consentvault.record_export_record (org_id, record_id);
ALTER TABLE consentvault.record_export_link ADD COLUMN revoked_at timestamptz;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['record_export_key', 'record_export_record'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I AS RESTRICTIVE FOR SELECT'
                       ' USING ((SELECT consentvault.may_read_record_exports()))', t || '_read_scope', t);
        EXECUTE format('REVOKE ALL ON consentvault.%I FROM PUBLIC', t);
    END LOOP;
END
$$;
GRANT SELECT ON consentvault.record_export_key TO consentvault_app;
-- the records jobs login writes the key and the membership when it builds, and destroys the key when the 24 hours are up
GRANT SELECT, INSERT ON consentvault.record_export_record TO consentvault_records_jobs;
GRANT SELECT, INSERT ON consentvault.record_export_key TO consentvault_records_jobs;
GRANT UPDATE (wrapped, destroyed_at, object_state) ON consentvault.record_export_key TO consentvault_records_jobs;

CREATE OR REPLACE FUNCTION consentvault.erase_contact(p_contact_fp text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.lifecycle_lock();
    h   uuid;
    n   integer;
    hit uuid[];
BEGIN
    IF p_contact_fp IS NULL OR p_contact_fp !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'consentvault erase: the fingerprint must be 64 hex characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF NOT coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'worker:restore'], false) THEN
        RAISE EXCEPTION 'consentvault erase: an admin or restore token is required' USING ERRCODE = 'insufficient_privilege';
    END IF;
    h := consentvault.legal_hold_covering(p_contact_fp);
    IF h IS NOT NULL THEN
        RAISE EXCEPTION 'legal_hold_active:%', h USING ERRCODE = 'integrity_constraint_violation',
            DETAIL = 'a legal hold covers this contact; its key is not deleted';
    END IF;
    DELETE FROM consentvault.contact_key k WHERE k.org_id = org AND k.contact_fp = p_contact_fp;
    GET DIAGNOSTICS n = ROW_COUNT;
    DELETE FROM consentvault.record_display d
     USING consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND d.org_id = r.org_id AND d.record_id = r.record_id;
    UPDATE consentvault.record_index i SET mask_ct = NULL
      FROM consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND i.org_id = r.org_id AND i.record_id = r.record_id
       AND i.mask_ct IS NOT NULL;
    UPDATE consentvault.record SET erased_at = clock_timestamp()
     WHERE org_id = org AND contact_fp = p_contact_fp AND erased_at IS NULL;
    -- Records list exports (records.md section 7): an export that holds a record of this contact point is destroyed in this
    -- transaction. It is marked expired, its links are revoked and its data key is destroyed, so the stored file, which may sit
    -- under retention and cannot be counted on to delete, can no longer be opened by anyone.
    PERFORM pg_advisory_xact_lock(hashtext('records_export_shred:' || org::text));
    SELECT coalesce(array_agg(DISTINCT m.export_id), '{}') INTO hit
      FROM consentvault.record_export_record m
      JOIN consentvault.record r ON r.org_id = m.org_id AND r.record_id = m.record_id
     WHERE m.org_id = org AND r.contact_fp = p_contact_fp;
    UPDATE consentvault.record_export e
       SET status = 'expired', expires_at = least(coalesce(e.expires_at, clock_timestamp()), clock_timestamp())
     WHERE e.org_id = org AND e.export_id = ANY (hit) AND e.status IN ('building', 'ready');
    UPDATE consentvault.record_export_link l SET revoked_at = clock_timestamp()
     WHERE l.org_id = org AND l.export_id = ANY (hit) AND l.revoked_at IS NULL;
    UPDATE consentvault.record_export_key k SET wrapped = NULL, destroyed_at = clock_timestamp()
     WHERE k.org_id = org AND k.export_id = ANY (hit) AND k.destroyed_at IS NULL;
    -- Confirmation messages (confirmations.md section 7): no sealed number survives the erasure of its contact. Queued sends to the
    -- contact are cancelled, every reply intent loses its sealed destination and text, and what the contact wrote from a number
    -- that was kept under the organization's display key is deleted, all in this transaction.
    UPDATE consentvault.confirmation_send_intent
       SET status = 'skipped', skip_reason = 'contact_erased', next_attempt_at = NULL, at = clock_timestamp()
     WHERE org_id = org AND contact_fp = p_contact_fp AND status = 'intent';
    UPDATE consentvault.confirmation_send_intent SET dest_ct = NULL, body_ct = NULL
     WHERE org_id = org AND contact_fp = p_contact_fp AND (dest_ct IS NOT NULL OR body_ct IS NOT NULL);
    DELETE FROM consentvault.confirmation_reply WHERE org_id = org AND from_fp = p_contact_fp AND key_kind = 'org';
    DELETE FROM consentvault.confirmation_connect_test WHERE org_id = org AND from_fp = p_contact_fp;
    RETURN n > 0;
END;
$$;
