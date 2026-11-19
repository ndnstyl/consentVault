-- Reverses 0114_stop_notice.sql: the stop notices, their email queue, acknowledgements and added recipients go with their tables.
BEGIN;

DO $$
BEGIN
    IF to_regclass('consentvault.stop_notice') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0114 refused: 0114 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.notify_send_log WHERE type = 'stop_notice') THEN
        RAISE EXCEPTION 'consentvault down 0114 refused: the send log holds stop_notice rows (append-only); keep the type';
    END IF;
END
$$;

-- erase_contact returns to 0112's body (no stop-notice statement); the notice tables are dropped below.
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
    -- Record links (competitive-builds, Build 1): every link to a record of this contact is withdrawn here, so a link never outlives
    -- the key. A link already withdrawn keeps its first withdrawal.
    INSERT INTO consentvault.proof_share_revocation (org_id, share_id, revoked_by, reason)
    SELECT s.org_id, s.share_id, 'erasure', 'erasure'
      FROM consentvault.proof_share s
      JOIN consentvault.event ev ON ev.org_id = s.org_id AND ev.event_id = s.event_id
     WHERE s.org_id = org AND ev.contact_fp = p_contact_fp
    ON CONFLICT (org_id, share_id) DO NOTHING;
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

DROP FUNCTION consentvault.stop_notice_acknowledge(uuid[]);
DROP FUNCTION consentvault.stop_notice_unacknowledged(integer);
DROP FUNCTION consentvault.stop_notice_member();
DROP FUNCTION consentvault.stop_notice_delivery(uuid[]);
DROP FUNCTION consentvault.stop_notice_mail_done(uuid[], boolean, integer);
DROP FUNCTION consentvault.stop_notice_claim(integer, integer, integer, integer, uuid[]);
DROP FUNCTION consentvault.stop_notice_sweep(integer);
DROP FUNCTION consentvault.stop_notice_record(uuid, uuid, text, bytea, text, text[], text[], jsonb, timestamptz);
DROP TABLE consentvault.stop_notice_ack;
DROP TABLE consentvault.stop_notice_mail;
DROP TABLE consentvault.stop_notice_recipient;
DROP TABLE consentvault.stop_notice;
ALTER TABLE consentvault.notify_send_log DROP CONSTRAINT notify_send_log_type_check;
ALTER TABLE consentvault.notify_send_log ADD CONSTRAINT notify_send_log_type_check
    CHECK (type IN ('invite', 'security_alert', 'delivery_failure', 'billing_notice'));

COMMIT;
