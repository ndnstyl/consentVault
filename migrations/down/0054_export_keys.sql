-- Undo 0054: erase_contact goes back to its 0052 body, the link loses revoked_at, and the export key tables go. Exports built under
-- their own keys cannot be opened afterwards (their keys go with the table); they are at most 24 hours old.
BEGIN;
CREATE OR REPLACE FUNCTION consentvault.erase_contact(p_contact_fp text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.lifecycle_lock();
    h   uuid;
    n   integer;
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
ALTER TABLE consentvault.record_export_link DROP COLUMN revoked_at;
DO $$
BEGIN
    IF to_regclass('consentvault_guard.table_pin') IS NOT NULL THEN
        DELETE FROM consentvault_guard.table_pin WHERE rel IN ('consentvault.record_export_key'::regclass,
            'consentvault.record_export_record'::regclass);
    END IF;
END
$$;
DROP TABLE consentvault.record_export_record;
DROP TABLE consentvault.record_export_key;
COMMIT;
