-- Undo 0060: the Twenty connector goes. Refuses loudly (and changes nothing) while any row still needs it: a Twenty system, a
-- clear or refresh push, a push with no channel, a disconnected system, an erasure waiting on a system clear or carrying a waiver,
-- or a connector-only error class. Every constraint and function 0060 changed goes back to its earlier body (sync_enqueue of
-- 0004, sync_claim of 0017, the key census and re-wrap of 0055).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM consentvault.connected_system WHERE connector <> 'generic_webhook' OR status = 'disconnected'
                  OR signature = 'none' OR credentials_ct IS NULL)
       OR EXISTS (SELECT 1 FROM consentvault.outbox WHERE push_kind <> 'state' OR channel IS NULL OR purpose IS NULL)
       OR EXISTS (SELECT 1 FROM consentvault.outbox
                   WHERE last_error_class IN ('readback_mismatch', 'schema_changed', 'target_private', 'key_rejected'))
       OR EXISTS (SELECT 1 FROM consentvault.delivery
                   WHERE error_class IN ('readback_mismatch', 'schema_changed', 'target_private', 'key_rejected'))
       OR EXISTS (SELECT 1 FROM consentvault.erasure_request WHERE wait_reason IN ('waiting_for_system_clear', 'system_clear_dead')
                     OR clear_waived_by IS NOT NULL) THEN
        RAISE EXCEPTION 'undo 0060 refused: rows of the Twenty connector still exist; disconnect and drain them first'
            USING ERRCODE = 'object_in_use';
    END IF;
END
$$;

REVOKE SELECT (org_id, secret_id, wrapped) ON consentvault.connector_secret FROM consentvault_console;
CREATE OR REPLACE FUNCTION consentvault.key_version_census_of(p_org uuid, p_version integer) RETURNS TABLE (kind text, n bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT 'contact_key', count(*) FROM consentvault.contact_key WHERE org_id = p_org AND key_version = p_version
    UNION ALL
    SELECT 'fingerprint_secret', count(*) FROM consentvault.org_fingerprint_secret
     WHERE org_id = p_org AND consentvault.wrap_version(wrapped) = p_version
    UNION ALL
    SELECT 'display_key', count(*) FROM consentvault.org_display_key
     WHERE org_id = p_org AND consentvault.wrap_version(wrapped) = p_version
    UNION ALL
    SELECT 'credential', count(*) FROM consentvault.credential
     WHERE org_id = p_org AND secret_ct IS NOT NULL AND consentvault.wrap_version(secret_ct) = p_version
    UNION ALL
    SELECT 'connected_system', count(*) FROM consentvault.connected_system
     WHERE org_id = p_org AND credentials_ct IS NOT NULL AND consentvault.wrap_version(credentials_ct) = p_version
    UNION ALL
    SELECT 'sending_account', count(*) FROM consentvault.sending_account a
     WHERE a.org_id = p_org AND ((a.credentials_ct IS NOT NULL AND consentvault.wrap_version(a.credentials_ct) = p_version)
                                 OR (a.auth_token_ct IS NOT NULL AND consentvault.wrap_version(a.auth_token_ct) = p_version))
    UNION ALL
    SELECT 'export_key', count(*) FROM consentvault.record_export_key
     WHERE org_id = p_org AND wrapped IS NOT NULL AND consentvault.wrap_version(wrapped) = p_version
    UNION ALL
    SELECT 'final_export', count(*) FROM consentvault.offboarding_request
     WHERE org_id = p_org AND final_export_wrapped IS NOT NULL AND consentvault.wrap_version(final_export_wrapped) = p_version
    UNION ALL
    SELECT 'hold_reason', count(*) FROM consentvault.legal_hold
     WHERE org_id = p_org AND (consentvault.sealed_version(reason) = p_version
                               OR consentvault.sealed_version(release_reason) = p_version);
$$;

CREATE OR REPLACE FUNCTION consentvault.rewrap_org_secret(p_kind text, p_ref uuid, p_old bytea, p_new bytea) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.current_org();
    n   integer;
BEGIN
    PERFORM consentvault.rewrap_target_ok(org, consentvault.wrap_version(p_new));
    IF p_old IS NULL OR consentvault.wrap_version(p_new) <= consentvault.wrap_version(p_old) THEN
        RAISE EXCEPTION 'consentvault re-wrap refused: a secret moves to a newer key version'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM set_config('consentvault.rewrap', 'on', true);
    IF p_kind = 'fingerprint_secret' THEN
        UPDATE consentvault.org_fingerprint_secret SET wrapped = p_new WHERE org_id = org AND wrapped = p_old;
    ELSIF p_kind = 'display_key' THEN
        UPDATE consentvault.org_display_key SET wrapped = p_new, key_version = consentvault.wrap_version(p_new)
         WHERE org_id = org AND wrapped = p_old;
    ELSIF p_kind = 'credential' THEN
        UPDATE consentvault.credential SET secret_ct = p_new
         WHERE org_id = org AND credential_id = p_ref AND secret_ct = p_old;
    ELSIF p_kind = 'connected_system' THEN
        UPDATE consentvault.connected_system SET credentials_ct = p_new
         WHERE org_id = org AND system_id = p_ref AND credentials_ct = p_old;
    ELSIF p_kind = 'export_key' THEN
        UPDATE consentvault.record_export_key SET wrapped = p_new, key_version = consentvault.wrap_version(p_new)
         WHERE org_id = org AND export_id = p_ref AND wrapped = p_old;
    ELSIF p_kind = 'sending_credentials' THEN
        UPDATE consentvault.sending_account SET credentials_ct = p_new
         WHERE org_id = org AND account_id = p_ref AND credentials_ct = p_old;
    ELSIF p_kind = 'sending_auth_token' THEN
        UPDATE consentvault.sending_account SET auth_token_ct = p_new
         WHERE org_id = org AND account_id = p_ref AND auth_token_ct = p_old;
    ELSE
        PERFORM set_config('consentvault.rewrap', 'off', true);
        RAISE EXCEPTION 'consentvault re-wrap refused: unknown secret kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('consentvault.rewrap', 'off', true);
    RETURN n = 1;
END;
$$;

CREATE OR REPLACE FUNCTION consentvault.sync_enqueue(p_outbox_id uuid, p_system_id uuid, p_contact_fp text, p_channel text,
                                          p_purpose text, p_version integer, p_payload_ct bytea) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org   uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
    added integer;
BEGIN
    PERFORM 1 FROM consentvault.state_version sv
     WHERE sv.org_id = org AND sv.contact_fp = p_contact_fp AND sv.channel = p_channel AND sv.purpose = p_purpose
       AND sv.version = p_version AND sv.advanced_txid = txid_current();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: refused, version % of that key was not advanced by this transaction', p_version
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    PERFORM 1 FROM consentvault.connected_system s WHERE s.org_id = org AND s.system_id = p_system_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: system % is not in the current organisation', p_system_id
            USING ERRCODE = 'no_data_found';
    END IF;
    INSERT INTO consentvault.outbox (org_id, outbox_id, system_id, contact_fp, channel, purpose, version, payload_ct,
                                     next_attempt_at)
    VALUES (org, p_outbox_id, p_system_id, p_contact_fp, p_channel, p_purpose, p_version, p_payload_ct, clock_timestamp())
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS added = ROW_COUNT;
    IF added = 0 THEN
        RETURN NULL;
    END IF;
    UPDATE consentvault.outbox o
       SET status = 'superseded', next_attempt_at = NULL, finished_at = clock_timestamp()
     WHERE o.org_id = org AND o.system_id = p_system_id AND o.contact_fp = p_contact_fp AND o.channel = p_channel
       AND o.purpose = p_purpose AND o.version < p_version AND o.status IN ('pending', 'failed');
    RETURN p_outbox_id;
END;
$$;

CREATE OR REPLACE FUNCTION consentvault.sync_claim(p_limit integer, p_lease_seconds integer,
                                        p_now timestamptz DEFAULT clock_timestamp())
    RETURNS TABLE (outbox_id uuid, system_id uuid, system_name text, contact_fp text, channel text, purpose text,
                   version integer, payload_ct bytea, attempt integer, created_at timestamptz, window_start timestamptz,
                   endpoint text, signature text, contact_form text, retry_window_hours integer,
                   credentials_ct bytea, wrapped_key bytea, key_version integer)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 500 OR p_lease_seconds IS NULL OR p_lease_seconds < 5
       OR p_lease_seconds > 3600 OR p_now IS NULL THEN
        RAISE EXCEPTION 'consentvault sync: claim needs a limit of 1 to 500 and a lease of 5 to 3600 seconds'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A push whose contact key is gone has nothing left to push. An erasure waits for every push of the person to be
    -- delivered or dead, so reaching here means a key vanished some other way: one alarm row per push, never silent.
    WITH gone AS (
        UPDATE consentvault.outbox o
           SET status = 'superseded', next_attempt_at = NULL, claimed_until = NULL, finished_at = p_now
         WHERE o.org_id = org
           AND (o.status IN ('pending', 'failed') OR (o.status = 'sent' AND o.claimed_until <= p_now))
           AND NOT EXISTS (SELECT 1 FROM consentvault.contact_key ck WHERE ck.org_id = o.org_id AND ck.contact_fp = o.contact_fp)
        RETURNING o.outbox_id
    )
    INSERT INTO consentvault.operator_alarm (org_id, name, ref_kind, ref_id, error_class)
    SELECT org, 'sync.contact_key_missing', 'outbox', g.outbox_id, 'contact_key_missing' FROM gone g;
    -- the attempt a dead worker left open is over
    UPDATE consentvault.delivery d SET status = 'failed', error_class = 'timeout', at = p_now
      FROM consentvault.outbox o
     WHERE o.org_id = org AND o.status = 'sent' AND o.claimed_until <= p_now
       AND d.org_id = o.org_id AND d.outbox_id = o.outbox_id AND d.attempt = o.attempts AND d.status = 'sent';
    RETURN QUERY
    WITH cand AS (
        SELECT o.outbox_id AS oid
          FROM consentvault.outbox o
          JOIN consentvault.connected_system s
            ON s.org_id = o.org_id AND s.system_id = o.system_id AND s.status = 'active'
         WHERE o.org_id = org
           AND ((o.status IN ('pending', 'failed') AND o.next_attempt_at <= p_now)
                OR (o.status = 'sent' AND o.claimed_until <= p_now))
           AND EXISTS (SELECT 1 FROM consentvault.contact_key ck WHERE ck.org_id = o.org_id AND ck.contact_fp = o.contact_fp)
           AND NOT EXISTS (SELECT 1 FROM consentvault.outbox older
                            WHERE older.org_id = o.org_id AND older.system_id = o.system_id
                              AND older.contact_fp = o.contact_fp AND older.channel = o.channel
                              AND older.purpose = o.purpose AND older.version < o.version
                              AND older.status IN ('pending', 'failed', 'sent'))
         ORDER BY o.created_at, o.outbox_id
         LIMIT p_limit
           FOR UPDATE OF o SKIP LOCKED
    ), upd AS (
        UPDATE consentvault.outbox o
           SET status = 'sent', attempts = o.attempts + 1, next_attempt_at = NULL, last_attempt_at = p_now,
               claimed_until = p_now + p_lease_seconds * interval '1 second'
          FROM cand
         WHERE o.org_id = org AND o.outbox_id = cand.oid
        RETURNING o.*
    ), ins AS (
        INSERT INTO consentvault.delivery (org_id, outbox_id, attempt, status, at)
        SELECT org, u.outbox_id, u.attempts, 'sent', p_now FROM upd u
        RETURNING 1
    )
    SELECT u.outbox_id, u.system_id, s.name, u.contact_fp, u.channel, u.purpose, u.version, u.payload_ct, u.attempts,
           u.created_at, u.window_start, s.endpoint, s.signature, s.contact_form, s.retry_window_hours,
           s.credentials_ct, ck.wrapped_key, ck.key_version
      FROM upd u
      JOIN consentvault.connected_system s ON s.org_id = u.org_id AND s.system_id = u.system_id
      JOIN consentvault.contact_key ck ON ck.org_id = u.org_id AND ck.contact_fp = u.contact_fp
     ORDER BY u.created_at, u.outbox_id;
END;
$$;

DROP TRIGGER contact_key_drops_connector_links ON consentvault.contact_key;
DROP TRIGGER connected_system_twenty_address_guard ON consentvault.connected_system;
DROP FUNCTION consentvault.sync_echo_targets();
DROP FUNCTION consentvault.connector_hints_of(uuid, text);
DROP FUNCTION consentvault.connector_hint_put(uuid, text, text, bytea);
DROP FUNCTION consentvault.connector_requests_with_clear(text[]);
DROP FUNCTION consentvault.connector_clear_supersede(uuid, text, text[], uuid, boolean);
DROP FUNCTION consentvault.connector_waivable(uuid);
DROP FUNCTION consentvault.sync_twenty_disconnect(uuid, text);
DROP FUNCTION consentvault.sync_twenty_set_address(uuid, text, bytea, bytea, text);
DROP FUNCTION consentvault.sync_receiver_resolve(text);
DROP FUNCTION consentvault.connector_receiver_mint(uuid, text);
DROP FUNCTION consentvault.connector_secret_put(uuid, text, bytea, bytea);
DROP FUNCTION consentvault.connector_secret_get(uuid, text);
DROP FUNCTION consentvault.connector_erased_points(text[]);
DROP FUNCTION consentvault.sync_contact_sealed(text);
DROP FUNCTION consentvault.connector_write_pending(uuid, text[]);
DROP FUNCTION consentvault.connector_reconcile_done(uuid, boolean, timestamptz, boolean);
DROP FUNCTION consentvault.connector_systems();
DROP FUNCTION consentvault.connector_set_state(uuid, text);
DROP FUNCTION consentvault.connector_activity_of(uuid, timestamptz);
DROP FUNCTION consentvault.connector_window_hit(uuid, text, integer, integer);
DROP FUNCTION consentvault.connector_count(uuid, text, bigint);
DROP FUNCTION consentvault.connector_flag_seen_set(uuid, text, boolean);
DROP FUNCTION consentvault.connector_flag_seen_get(uuid, text);
DROP FUNCTION consentvault.connector_sweep_destroyed();
DROP FUNCTION consentvault.connector_is_destroyed(uuid, text);
DROP FUNCTION consentvault.connector_destroy(uuid, text);
DROP FUNCTION consentvault.connector_person_back(uuid, text);
DROP FUNCTION consentvault.connector_deleted_wait(uuid, text, text);
DROP FUNCTION consentvault.connector_link_put(uuid, text, text, bytea, bigint, boolean);
DROP FUNCTION consentvault.connector_links_of(uuid, text[], text);
DROP FUNCTION consentvault.sync_complete_connector(uuid, integer, text, integer, text, bytea, integer, text);
DROP FUNCTION consentvault.sync_rate_take(uuid, integer);
DROP FUNCTION consentvault.sync_person_state(uuid, text[]);
DROP FUNCTION consentvault.sync_release_person(uuid, text, uuid);
DROP FUNCTION consentvault.sync_lease_person(uuid, text, uuid, integer);
DROP FUNCTION consentvault.sync_extend_lease(uuid[], integer[], integer);
DROP FUNCTION consentvault.sync_claim_person(integer);
DROP FUNCTION consentvault.sync_request_reconcile(uuid);
DROP FUNCTION consentvault.connector_lifecycle_locked();
DROP FUNCTION consentvault.sync_enqueue_clear(uuid, uuid, uuid, bytea);
DROP FUNCTION consentvault.sync_enqueue_refresh(uuid, uuid, text, bytea);
DROP FUNCTION consentvault.connector_erasure_midflight(uuid, uuid, text);
DROP FUNCTION consentvault.connector_org(uuid, text[], boolean);
DROP FUNCTION consentvault.connector_link_drop_with_key();
DROP FUNCTION consentvault.connected_system_twenty_address_guard();

DROP TABLE consentvault.connector_window_mark, consentvault.connector_point_hint, consentvault.connector_reconcile, consentvault.connector_flag_seen, consentvault.connector_activity,
    consentvault.connector_rate, consentvault.connector_receiver, consentvault.connector_destroyed,
    consentvault.connector_person_lease, consentvault.connector_link, consentvault.connector_secret;
REVOKE SELECT (org_id, system_id, status, connector) ON consentvault.connected_system FROM consentvault_operator;

ALTER TABLE consentvault.erasure_request DROP CONSTRAINT erasure_request_wait_reason_check;
ALTER TABLE consentvault.erasure_request ADD CONSTRAINT erasure_request_wait_reason_check
    CHECK (wait_reason IS NULL OR wait_reason IN ('pending_suppression_delivery', 'uncommitted_ledger_intent'));
ALTER TABLE consentvault.erasure_request DROP CONSTRAINT erasure_request_waiver_shape;
ALTER TABLE consentvault.erasure_request DROP COLUMN clear_waived_by, DROP COLUMN clear_waived_at, DROP COLUMN clear_waived_reason;

ALTER TABLE consentvault.delivery DROP CONSTRAINT delivery_error_class_check;
ALTER TABLE consentvault.delivery ADD CONSTRAINT delivery_error_class_check
    CHECK (error_class IN ('timeout', 'http_4xx', 'http_5xx', 'signature_rejected', 'unreachable', 'prepare_failed'));
ALTER TABLE consentvault.outbox DROP CONSTRAINT outbox_last_error_class_check;
ALTER TABLE consentvault.outbox ADD CONSTRAINT outbox_last_error_class_check
    CHECK (last_error_class IN ('timeout', 'http_4xx', 'http_5xx', 'signature_rejected', 'unreachable', 'prepare_failed'));
DROP INDEX consentvault.outbox_person_group_idx;
DROP INDEX consentvault.outbox_refresh_one_open_idx;
DROP INDEX consentvault.outbox_clear_one_per_request_idx;
DROP INDEX consentvault.outbox_state_idempotency_idx;
ALTER TABLE consentvault.outbox ADD CONSTRAINT outbox_org_id_system_id_contact_fp_channel_purpose_version_key
    UNIQUE (org_id, system_id, contact_fp, channel, purpose, version);
ALTER TABLE consentvault.outbox DROP CONSTRAINT outbox_kind_shape;
ALTER TABLE consentvault.outbox ALTER COLUMN channel SET NOT NULL, ALTER COLUMN purpose SET NOT NULL;
ALTER TABLE consentvault.outbox DROP COLUMN push_kind, DROP COLUMN priority, DROP COLUMN confirmation, DROP COLUMN confirmed_at,
    DROP COLUMN erasure_id, DROP COLUMN superseded_reason;

ALTER TABLE consentvault.connected_system DROP CONSTRAINT connected_system_echo_twenty_only;
ALTER TABLE consentvault.connected_system DROP COLUMN echo_to_source, DROP COLUMN connector_state, DROP COLUMN reconcile_requested_at;
ALTER TABLE consentvault.connected_system DROP CONSTRAINT connected_system_twenty_plaintext;
ALTER TABLE consentvault.connected_system DROP CONSTRAINT connected_system_connector_known;
ALTER TABLE consentvault.connected_system DROP CONSTRAINT connected_system_status_known;
ALTER TABLE consentvault.connected_system ADD CONSTRAINT connected_system_status_check CHECK (status IN ('active', 'paused'));
ALTER TABLE consentvault.connected_system ADD CONSTRAINT connected_system_status_admin CHECK (status IN ('active', 'paused'));
ALTER TABLE consentvault.connected_system DROP CONSTRAINT connected_system_signature_kind;
ALTER TABLE consentvault.connected_system ADD CONSTRAINT connected_system_signature_check CHECK (signature IN ('ed25519', 'hmac'));
ALTER TABLE consentvault.connected_system ADD CONSTRAINT connected_system_signature_admin
    CHECK (signature IS NULL OR signature IN ('ed25519', 'hmac'));
ALTER TABLE consentvault.connected_system DROP CONSTRAINT connected_system_generic_credentials;
ALTER TABLE consentvault.connected_system ALTER COLUMN credentials_ct SET NOT NULL;
