-- The Twenty CRM connector (contracts: twenty.md sections 1 to 9; the erasure state machine in the Twenty erasure model).
--
-- Not purely additive. What changes, each keeping the generic webhook's rule through a connector guard:
--   connected_system  credentials_ct may be NULL for a non-generic connector; signature 'none' for a non-generic connector;
--                     status gains 'disconnected'; connector is one of the known names; a Twenty system is plaintext;
--                     new echo_to_source, connector_state, reconcile_requested_at.
--   outbox            push_kind (state | refresh | clear), priority (0 denied first), confirmation and confirmed_at,
--                     erasure_id (a clear's request), superseded_reason; channel and purpose may be NULL for a clear or a
--                     refresh only; the idempotency key becomes a partial unique index for state rows, plus one clear per
--                     (system, erasure) and one OPEN refresh per (system, contact); the error class lists gain
--                     readback_mismatch, schema_changed, target_private, key_rejected.
--   erasure_request   clear_waived_by, clear_waived_at, clear_waived_reason; wait reasons gain waiting_for_system_clear and
--                     system_clear_dead.
--   sync_enqueue      priority, and a status push to a Twenty system is inserted superseded while an erasure of that contact
--                     is mid-flight there (its clear open, dead or acknowledged, the request pending and not held).
--   sync_claim        generic rows only (a Twenty push is claimed one person group at a time by sync_claim_person); a push
--                     dropped because its contact key is gone carries superseded_reason 'erased'.
--   key rotation      the census and the re-wrap learn the kind 'connector_secret' (bodies of 0055 plus that kind).
-- New tables (nine): connector_secret, connector_link, connector_person_lease, connector_destroyed, connector_receiver,
-- connector_rate, connector_activity, connector_flag_seen, connector_reconcile. A contact key's delete removes that contact's
-- connector_link rows in the same transaction (trigger), so erase_contact and a restore's replay both drop them; the rows of
-- the Person's other contacts stay.
-- No column of consent.event, of the evidence tables or of any sealed column is dropped, renamed or retyped.

-- 1. connected_system --------------------------------------------------------------------------------------------------
ALTER TABLE consentvault.connected_system ALTER COLUMN credentials_ct DROP NOT NULL;
ALTER TABLE consentvault.connected_system
    ADD CONSTRAINT connected_system_generic_credentials CHECK (connector <> 'generic_webhook' OR credentials_ct IS NOT NULL);
ALTER TABLE consentvault.connected_system DROP CONSTRAINT connected_system_signature_check;
ALTER TABLE consentvault.connected_system DROP CONSTRAINT connected_system_signature_admin;
ALTER TABLE consentvault.connected_system ADD CONSTRAINT connected_system_signature_kind
    CHECK (signature IN ('ed25519', 'hmac') OR (signature = 'none' AND connector <> 'generic_webhook'));
ALTER TABLE consentvault.connected_system DROP CONSTRAINT connected_system_status_check;
ALTER TABLE consentvault.connected_system DROP CONSTRAINT connected_system_status_admin;
ALTER TABLE consentvault.connected_system ADD CONSTRAINT connected_system_status_known
    CHECK (status IN ('active', 'paused', 'disconnected'));
ALTER TABLE consentvault.connected_system ADD CONSTRAINT connected_system_connector_known
    CHECK (connector IN ('generic_webhook', 'twenty'));
ALTER TABLE consentvault.connected_system ADD CONSTRAINT connected_system_twenty_plaintext
    CHECK (connector <> 'twenty' OR contact_form = 'plaintext');
ALTER TABLE consentvault.connected_system
    ADD COLUMN echo_to_source boolean NOT NULL DEFAULT false,
    ADD COLUMN connector_state text CHECK (connector_state IS NULL OR connector_state IN (
        'healthy', 'connecting', 'needs_attention:key_rejected', 'needs_attention:fields_missing',
        'needs_attention:version_untested', 'needs_attention:schema_changed', 'needs_attention:webhook_failing',
        'unreachable_private', 'unreachable')),
    ADD COLUMN reconcile_requested_at timestamptz;
ALTER TABLE consentvault.connected_system ADD CONSTRAINT connected_system_echo_twenty_only
    CHECK (NOT echo_to_source OR connector = 'twenty');

-- A Twenty system's address changes only through sync_twenty_set_address, which requires the API key again in the same call
-- (twenty.md 1.1): the admin lane's ordinary column grant on endpoint cannot move a stored key to a new address.
CREATE FUNCTION consentvault.connected_system_twenty_address_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF OLD.connector = 'twenty' AND NEW.endpoint IS DISTINCT FROM OLD.endpoint
       AND coalesce(current_setting('consentvault.twenty_address_change', true), '') <> OLD.system_id::text THEN
        RAISE EXCEPTION 'consentvault: a Twenty system''s address changes only with its API key entered again'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.connector IS DISTINCT FROM NEW.connector THEN
        RAISE EXCEPTION 'consentvault: a system''s connector never changes' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF OLD.status = 'disconnected' AND NEW.status <> 'disconnected' THEN
        RAISE EXCEPTION 'consentvault: a disconnected system is never reconnected; connect a new one'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER connected_system_twenty_address_guard BEFORE UPDATE ON consentvault.connected_system
    FOR EACH ROW EXECUTE FUNCTION consentvault.connected_system_twenty_address_guard();

-- 2. outbox ------------------------------------------------------------------------------------------------------------
ALTER TABLE consentvault.outbox
    ADD COLUMN push_kind text NOT NULL DEFAULT 'state' CHECK (push_kind IN ('state', 'clear', 'refresh')),
    ADD COLUMN priority smallint NOT NULL DEFAULT 1 CHECK (priority IN (0, 1)),
    ADD COLUMN confirmation text CHECK (confirmation IS NULL OR confirmation IN ('applied', 'not_in_system', 'mismatch', 'cleared')),
    ADD COLUMN confirmed_at timestamptz,
    ADD COLUMN erasure_id uuid,
    ADD COLUMN superseded_reason text CHECK (superseded_reason IS NULL OR superseded_reason IN (
        'newer', 'held', 'declined', 'waived', 'erased', 'system_disconnected'));
ALTER TABLE consentvault.outbox ALTER COLUMN channel DROP NOT NULL, ALTER COLUMN purpose DROP NOT NULL;
ALTER TABLE consentvault.outbox ADD CONSTRAINT outbox_kind_shape CHECK (
    (push_kind = 'state' AND channel IS NOT NULL AND purpose IS NOT NULL AND erasure_id IS NULL)
    OR (push_kind = 'refresh' AND channel IS NULL AND purpose IS NULL AND erasure_id IS NULL)
    OR (push_kind = 'clear' AND channel IS NULL AND purpose IS NULL AND erasure_id IS NOT NULL));
-- No foreign key to erasure_request: a clear is only ever inserted by sync_enqueue_clear, which reads the request it names in
-- this organisation, and the erasure lane's own down file must stay able to drop its table on an empty install.
ALTER TABLE consentvault.outbox DROP CONSTRAINT outbox_org_id_system_id_contact_fp_channel_purpose_version_key;
CREATE UNIQUE INDEX outbox_state_idempotency_idx ON consentvault.outbox (org_id, system_id, contact_fp, channel, purpose, version)
    WHERE push_kind = 'state';
CREATE UNIQUE INDEX outbox_clear_one_per_request_idx ON consentvault.outbox (org_id, system_id, erasure_id)
    WHERE push_kind = 'clear';
CREATE UNIQUE INDEX outbox_refresh_one_open_idx ON consentvault.outbox (org_id, system_id, contact_fp)
    WHERE push_kind = 'refresh' AND status IN ('pending', 'failed', 'sent');
CREATE INDEX outbox_person_group_idx ON consentvault.outbox (org_id, system_id, contact_fp)
    WHERE status IN ('pending', 'failed', 'sent');
ALTER TABLE consentvault.outbox DROP CONSTRAINT outbox_last_error_class_check;
ALTER TABLE consentvault.outbox ADD CONSTRAINT outbox_last_error_class_check
    CHECK (last_error_class IN ('timeout', 'http_4xx', 'http_5xx', 'signature_rejected', 'unreachable', 'prepare_failed',
                                'readback_mismatch', 'schema_changed', 'target_private', 'key_rejected'));
ALTER TABLE consentvault.delivery DROP CONSTRAINT delivery_error_class_check;
ALTER TABLE consentvault.delivery ADD CONSTRAINT delivery_error_class_check
    CHECK (error_class IN ('timeout', 'http_4xx', 'http_5xx', 'signature_rejected', 'unreachable', 'prepare_failed',
                           'readback_mismatch', 'schema_changed', 'target_private', 'key_rejected'));

-- 3. erasure_request ---------------------------------------------------------------------------------------------------
ALTER TABLE consentvault.erasure_request
    ADD COLUMN clear_waived_by text,
    ADD COLUMN clear_waived_at timestamptz,
    ADD COLUMN clear_waived_reason text CHECK (clear_waived_reason IS NULL OR length(clear_waived_reason) BETWEEN 1 AND 500);
ALTER TABLE consentvault.erasure_request ADD CONSTRAINT erasure_request_waiver_shape
    CHECK ((clear_waived_by IS NULL) = (clear_waived_at IS NULL) AND (clear_waived_by IS NULL) = (clear_waived_reason IS NULL));
ALTER TABLE consentvault.erasure_request DROP CONSTRAINT erasure_request_wait_reason_check;
ALTER TABLE consentvault.erasure_request ADD CONSTRAINT erasure_request_wait_reason_check
    CHECK (wait_reason IS NULL OR wait_reason IN ('pending_suppression_delivery', 'uncommitted_ledger_intent',
                                                  'waiting_for_system_clear', 'system_clear_dead'));

-- 4. New tables --------------------------------------------------------------------------------------------------------
-- An envelope-sealed secret: a fresh 32-byte key sealed the secret (AES-GCM, authenticated data org, system, purpose), and the
-- organisation key wraps that key (``wrapped``). The connector hash key is 32 random bytes wrapped directly (``sealed`` NULL).
CREATE TABLE consentvault.connector_secret (
    org_id     uuid NOT NULL REFERENCES consentvault.organization (org_id),
    secret_id  uuid NOT NULL DEFAULT gen_random_uuid(),
    system_id  uuid,
    purpose    text NOT NULL CHECK (purpose IN ('api_key', 'webhook_secret', 'hash_key')),
    wrapped    bytea NOT NULL,
    sealed     bytea,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, secret_id),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id),
    CONSTRAINT connector_secret_shape CHECK ((purpose = 'hash_key') = (system_id IS NULL) AND (purpose = 'hash_key') = (sealed IS NULL))
);
CREATE UNIQUE INDEX connector_secret_one_per_purpose_idx ON consentvault.connector_secret (org_id, system_id, purpose)
    WHERE system_id IS NOT NULL;
CREATE UNIQUE INDEX connector_secret_one_hash_key_idx ON consentvault.connector_secret (org_id) WHERE purpose = 'hash_key';

CREATE TABLE consentvault.connector_link (
    org_id             uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id          uuid NOT NULL,
    person_id_hash     text NOT NULL CHECK (person_id_hash ~ '^[0-9a-f]{64}$'),
    contact_fp         text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    person_id_ct       bytea NOT NULL,
    last_seq_written   bigint,
    last_confirmed_seq bigint,
    confirmed_at       timestamptz,
    deleted_since      timestamptz,
    alarm_level        smallint NOT NULL DEFAULT 0 CHECK (alarm_level BETWEEN 0 AND 2),
    alarm_raised_at    timestamptz,
    alarm_raises       integer NOT NULL DEFAULT 0 CHECK (alarm_raises >= 0),
    created_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, system_id, person_id_hash, contact_fp),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id)
);
CREATE INDEX connector_link_contact_idx ON consentvault.connector_link (org_id, system_id, contact_fp);

CREATE TABLE consentvault.connector_person_lease (
    org_id         uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id      uuid NOT NULL,
    person_id_hash text NOT NULL CHECK (person_id_hash ~ '^[0-9a-f]{64}$'),
    outbox_id      uuid NOT NULL,
    attempt        integer NOT NULL CHECK (attempt >= 1),
    lease_until    timestamptz NOT NULL,
    PRIMARY KEY (org_id, system_id, person_id_hash),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id)
);

CREATE TABLE consentvault.connector_destroyed (
    org_id         uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id      uuid NOT NULL,
    person_id_hash text NOT NULL CHECK (person_id_hash ~ '^[0-9a-f]{64}$'),
    destroyed_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, system_id, person_id_hash),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id)
);

-- The receiver id is a lookup credential: only its SHA-256 is stored. A retired id answers 404 like an unknown one.
CREATE TABLE consentvault.connector_receiver (
    org_id        uuid NOT NULL REFERENCES consentvault.organization (org_id),
    receiver_hash text NOT NULL UNIQUE CHECK (receiver_hash ~ '^[0-9a-f]{64}$'),
    system_id     uuid NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    retired_at    timestamptz,
    PRIMARY KEY (org_id, receiver_hash),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id)
);
CREATE UNIQUE INDEX connector_receiver_one_live_idx ON consentvault.connector_receiver (org_id, system_id) WHERE retired_at IS NULL;

CREATE TABLE consentvault.connector_rate (
    org_id      uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id   uuid NOT NULL,
    tokens      double precision NOT NULL CHECK (tokens >= 0),
    refilled_at timestamptz NOT NULL,
    PRIMARY KEY (org_id, system_id),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id)
);

-- Counts only: never a contact point, never a Twenty id.
CREATE TABLE consentvault.connector_activity (
    org_id    uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id uuid NOT NULL,
    day       date NOT NULL,
    name      text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]{0,63}$'),
    n         bigint NOT NULL CHECK (n >= 0),
    last_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, system_id, day, name),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id)
);

-- One row per hit the rolling-window alarms count (connector_window_hit); pruned as hits pass out of the window. Counts only.
CREATE TABLE consentvault.connector_window_mark (
    org_id    uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id uuid NOT NULL,
    name      text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]{0,40}$'),
    at        timestamptz NOT NULL,
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id)
);
CREATE INDEX connector_window_mark_by_name ON consentvault.connector_window_mark (org_id, system_id, name, at);

CREATE TABLE consentvault.connector_flag_seen (
    org_id         uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id      uuid NOT NULL,
    person_id_hash text NOT NULL CHECK (person_id_hash ~ '^[0-9a-f]{64}$'),
    flag           boolean NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, system_id, person_id_hash),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id)
);

-- A contact point an event named on a Person (twenty.md 1.7): Twenty's filter reaches only the primary email and phone, so the
-- receiver remembers every point a Person carries, whether or not the vault holds that contact yet, and a delivery with no link
-- for the contact finds the Person here. The Person id is sealed under the organisation's connector hash key (it is a record id,
-- no contact data); the row goes with the contact's key, a hard delete of the Person, and a disconnect.
CREATE TABLE consentvault.connector_point_hint (
    org_id         uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id      uuid NOT NULL,
    person_id_hash text NOT NULL CHECK (person_id_hash ~ '^[0-9a-f]{64}$'),
    contact_fp     text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    person_id_ct   bytea NOT NULL,
    noted_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, system_id, person_id_hash, contact_fp),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id)
);

CREATE TABLE consentvault.connector_reconcile (
    org_id            uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id         uuid NOT NULL,
    watermark         timestamptz,
    last_run_at       timestamptz,
    last_ok_at        timestamptz,
    failures_in_row   integer NOT NULL DEFAULT 0 CHECK (failures_in_row >= 0),
    last_full_scan_at timestamptz,
    PRIMARY KEY (org_id, system_id),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id)
);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['connector_secret', 'connector_link', 'connector_person_lease', 'connector_destroyed',
                             'connector_receiver', 'connector_rate', 'connector_activity', 'connector_flag_seen',
                             'connector_reconcile', 'connector_point_hint', 'connector_window_mark'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
        EXECUTE format('REVOKE ALL ON consentvault.%I FROM PUBLIC', t);
    END LOOP;
END
$$;
-- The receiver resolves its id before any tenant is entered (as resolve_site_key does): the operator role owns that one reader.
GRANT SELECT (org_id, receiver_hash, system_id, retired_at) ON consentvault.connector_receiver TO consentvault_operator;
GRANT SELECT (org_id, system_id, status, connector) ON consentvault.connected_system TO consentvault_operator;

-- A contact key's delete removes that contact's links in the same transaction (rule R18): erase_contact and a restore's
-- replay both go through it. connector_flag_seen and connector_person_lease are keyed by the Person and are not touched.
CREATE FUNCTION consentvault.connector_link_drop_with_key() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    DELETE FROM consentvault.connector_link l WHERE l.org_id = OLD.org_id AND l.contact_fp = OLD.contact_fp;
    DELETE FROM consentvault.connector_point_hint p WHERE p.org_id = OLD.org_id AND p.contact_fp = OLD.contact_fp;
    RETURN OLD;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.connector_link_drop_with_key() FROM PUBLIC;
CREATE TRIGGER contact_key_drops_connector_links AFTER DELETE ON consentvault.contact_key
    FOR EACH ROW EXECUTE FUNCTION consentvault.connector_link_drop_with_key();

-- 5. Shared checks -----------------------------------------------------------------------------------------------------
-- The organisation (after the scope check) when p_system_id is a Twenty system of it; refuses otherwise.
CREATE FUNCTION consentvault.connector_org(p_system_id uuid, p_any_scope text[], p_live boolean DEFAULT true) RETURNS uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(p_any_scope);
    st  text;
BEGIN
    SELECT s.status INTO st FROM consentvault.connected_system s
     WHERE s.org_id = org AND s.system_id = p_system_id AND s.connector = 'twenty';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault connector: system % is not a Twenty system of the current organisation', p_system_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF p_live AND st = 'disconnected' THEN
        RAISE EXCEPTION 'consentvault connector: system % is disconnected', p_system_id USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN org;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.connector_org(uuid, text[], boolean) FROM PUBLIC;

-- Is an erasure of this contact mid-flight on this system (rule R1): a pending, unheld request whose clear there is open, dead
-- or acknowledged.
CREATE FUNCTION consentvault.connector_erasure_midflight(p_org uuid, p_system_id uuid, p_contact_fp text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM consentvault.erasure_request r
          JOIN consentvault.outbox c ON c.org_id = r.org_id AND c.erasure_id = r.erasure_id AND c.push_kind = 'clear'
         WHERE r.org_id = p_org AND r.contact_fp = p_contact_fp AND c.system_id = p_system_id
           AND r.status = 'pending_operator_confirmation' AND r.held_by IS NULL
           AND c.status IN ('pending', 'failed', 'sent', 'dead', 'acknowledged'));
$$;
REVOKE ALL ON FUNCTION consentvault.connector_erasure_midflight(uuid, uuid, text) FROM PUBLIC;

-- 6. Capture side: sync_enqueue with priority and rule R1 ----------------------------------------------------------------
CREATE OR REPLACE FUNCTION consentvault.sync_enqueue(p_outbox_id uuid, p_system_id uuid, p_contact_fp text, p_channel text,
                                          p_purpose text, p_version integer, p_payload_ct bytea) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org   uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
    added integer;
    st    text;
    conn  text;
    supp  boolean := false;
BEGIN
    SELECT sv.state INTO st FROM consentvault.state_version sv
     WHERE sv.org_id = org AND sv.contact_fp = p_contact_fp AND sv.channel = p_channel AND sv.purpose = p_purpose
       AND sv.version = p_version AND sv.advanced_txid = txid_current();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: refused, version % of that key was not advanced by this transaction', p_version
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    SELECT s.connector INTO conn FROM consentvault.connected_system s WHERE s.org_id = org AND s.system_id = p_system_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: system % is not in the current organisation', p_system_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF conn = 'twenty' THEN
        supp := consentvault.connector_erasure_midflight(org, p_system_id, p_contact_fp);
    END IF;
    INSERT INTO consentvault.outbox (org_id, outbox_id, system_id, contact_fp, channel, purpose, version, payload_ct,
                                     next_attempt_at, priority, status, finished_at, superseded_reason)
    VALUES (org, p_outbox_id, p_system_id, p_contact_fp, p_channel, p_purpose, p_version, p_payload_ct,
            CASE WHEN supp THEN NULL ELSE clock_timestamp() END, CASE WHEN st = 'denied' THEN 0 ELSE 1 END,
            CASE WHEN supp THEN 'superseded' ELSE 'pending' END, CASE WHEN supp THEN clock_timestamp() END,
            CASE WHEN supp THEN 'erased' END)
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS added = ROW_COUNT;
    IF added = 0 OR supp THEN
        RETURN NULL;
    END IF;
    UPDATE consentvault.outbox o
       SET status = 'superseded', next_attempt_at = NULL, finished_at = clock_timestamp(), superseded_reason = 'newer'
     WHERE o.org_id = org AND o.system_id = p_system_id AND o.contact_fp = p_contact_fp AND o.channel = p_channel
       AND o.purpose = p_purpose AND o.version < p_version AND o.status IN ('pending', 'failed');
    RETURN p_outbox_id;
END;
$$;

-- A refresh push (twenty.md 2.1): no version, one open per (system, contact), the connector writes the ledger-derived state.
-- Obeys rule R1 like a state push, and is never queued for a contact with no key (erased, 3.7). NULL when nothing was queued.
CREATE FUNCTION consentvault.sync_enqueue_refresh(p_outbox_id uuid, p_system_id uuid, p_contact_fp text, p_payload_ct bytea)
    RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org   uuid := consentvault.connector_org(p_system_id, ARRAY['capture', 'capture_verified', 'admin', 'worker:sync']);
    added integer;
BEGIN
    IF p_contact_fp IS NULL OR p_contact_fp !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'consentvault connector: the fingerprint must be 64 hex characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM consentvault.contact_key k WHERE k.org_id = org AND k.contact_fp = p_contact_fp)
       OR consentvault.connector_erasure_midflight(org, p_system_id, p_contact_fp) THEN
        RETURN NULL;
    END IF;
    INSERT INTO consentvault.outbox (org_id, outbox_id, system_id, contact_fp, channel, purpose, version, payload_ct,
                                     next_attempt_at, push_kind, priority)
    VALUES (org, p_outbox_id, p_system_id, p_contact_fp, NULL, NULL, 1, p_payload_ct, clock_timestamp(), 'refresh', 0)
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS added = ROW_COUNT;
    RETURN CASE WHEN added = 0 THEN NULL ELSE p_outbox_id END;
END;
$$;

-- The clear of one erasure request on one Twenty system (twenty.md 5.1, 9.1 item 11). Checks, in order and nothing else: the
-- admin scope; the lifecycle lock held by this transaction; the request pending, unheld and in this organisation; the system a
-- Twenty system of it, active or paused. The fingerprint is read from the request. One clear per (system, request): a second
-- call returns the same row, reviving it only when it was superseded with reason 'held'. Queuing or reviving supersedes the
-- contact's queued status pushes to that system (rule R5).
CREATE FUNCTION consentvault.sync_enqueue_clear(p_erasure_id uuid, p_system_id uuid, p_outbox_id uuid, p_payload_ct bytea)
    RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org  uuid := consentvault.sync_org(ARRAY['admin']);
    req  record;
    st   text;
    cur  record;
    got  uuid;
BEGIN
    IF coalesce(current_setting('consentvault.lifecycle_locked', true), '') <> org::text THEN
        RAISE EXCEPTION 'consentvault connector: a clear is queued only under the lifecycle lock' USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    SELECT r.contact_fp AS fp, r.status AS status, r.held_by AS held INTO req FROM consentvault.erasure_request r
     WHERE r.org_id = org AND r.erasure_id = p_erasure_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault connector: erasure % is not in the current organisation', p_erasure_id USING ERRCODE = 'no_data_found';
    END IF;
    IF req.status <> 'pending_operator_confirmation' OR req.held IS NOT NULL THEN
        RAISE EXCEPTION 'consentvault connector: erasure % is not pending and unheld', p_erasure_id
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    SELECT s.status INTO st FROM consentvault.connected_system s
     WHERE s.org_id = org AND s.system_id = p_system_id AND s.connector = 'twenty';
    IF NOT FOUND OR st NOT IN ('active', 'paused') THEN
        RAISE EXCEPTION 'consentvault connector: system % is not a live Twenty system of this organisation', p_system_id
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    SELECT o.outbox_id AS id, o.status AS status, o.superseded_reason AS why INTO cur FROM consentvault.outbox o
     WHERE o.org_id = org AND o.system_id = p_system_id AND o.erasure_id = p_erasure_id AND o.push_kind = 'clear' FOR UPDATE;
    IF FOUND THEN
        got := cur.id;
        IF cur.status = 'superseded' AND cur.why = 'held' THEN
            UPDATE consentvault.outbox o SET status = 'pending', next_attempt_at = clock_timestamp(), finished_at = NULL,
                   superseded_reason = NULL, claimed_until = NULL, window_start = clock_timestamp()
             WHERE o.org_id = org AND o.outbox_id = cur.id;
        ELSE
            RETURN got;
        END IF;
    ELSE
        IF p_payload_ct IS NULL THEN
            RAISE EXCEPTION 'consentvault connector: a new clear needs its sealed marker body' USING ERRCODE = 'invalid_parameter_value';
        END IF;
        INSERT INTO consentvault.outbox (org_id, outbox_id, system_id, contact_fp, channel, purpose, version, payload_ct,
                                         next_attempt_at, push_kind, priority, erasure_id)
        VALUES (org, p_outbox_id, p_system_id, req.fp, NULL, NULL, 1, p_payload_ct, clock_timestamp(), 'clear', 0, p_erasure_id);
        got := p_outbox_id;
    END IF;
    UPDATE consentvault.outbox o
       SET status = 'superseded', next_attempt_at = NULL, finished_at = clock_timestamp(), superseded_reason = 'erased'
     WHERE o.org_id = org AND o.system_id = p_system_id AND o.contact_fp = req.fp AND o.push_kind IN ('state', 'refresh')
       AND o.status IN ('pending', 'failed');
    RETURN got;
END;
$$;

-- erase_in_org's lock marker: lifecycle_lock() is the existing advisory lock; sync_enqueue_clear asks whether this transaction
-- holds it. The marker is set by connector_lifecycle_locked(), which takes the lock itself.
CREATE FUNCTION consentvault.connector_lifecycle_locked() RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.lifecycle_lock();
BEGIN
    PERFORM set_config('consentvault.lifecycle_locked', org::text, true);
    RETURN org;
END;
$$;

CREATE FUNCTION consentvault.sync_request_reconcile(p_system_id uuid) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['capture', 'admin', 'worker:sync']);
BEGIN
    UPDATE consentvault.connected_system SET reconcile_requested_at = coalesce(reconcile_requested_at, clock_timestamp())
     WHERE org_id = org AND system_id = p_system_id;
END;
$$;

-- 7. Worker side --------------------------------------------------------------------------------------------------------
-- The generic claim, unchanged except that it takes generic rows only and orders stops first (a Twenty push is claimed by
-- sync_claim_person), and that a push dropped because its contact key is gone says why.
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
    WITH gone AS (
        UPDATE consentvault.outbox o
           SET status = 'superseded', next_attempt_at = NULL, claimed_until = NULL, finished_at = p_now,
               superseded_reason = 'erased'
         WHERE o.org_id = org
           AND (o.status IN ('pending', 'failed') OR (o.status = 'sent' AND o.claimed_until <= p_now))
           AND NOT EXISTS (SELECT 1 FROM consentvault.contact_key ck WHERE ck.org_id = o.org_id AND ck.contact_fp = o.contact_fp)
        RETURNING o.outbox_id
    )
    INSERT INTO consentvault.operator_alarm (org_id, name, ref_kind, ref_id, error_class)
    SELECT org, 'sync.contact_key_missing', 'outbox', g.outbox_id, 'contact_key_missing' FROM gone g;
    UPDATE consentvault.delivery d SET status = 'failed', error_class = 'timeout', at = p_now
      FROM consentvault.outbox o
     WHERE o.org_id = org AND o.status = 'sent' AND o.claimed_until <= p_now
       AND d.org_id = o.org_id AND d.outbox_id = o.outbox_id AND d.attempt = o.attempts AND d.status = 'sent';
    RETURN QUERY
    WITH cand AS (
        SELECT o.outbox_id AS oid
          FROM consentvault.outbox o
          JOIN consentvault.connected_system s
            ON s.org_id = o.org_id AND s.system_id = o.system_id AND s.status = 'active' AND s.connector = 'generic_webhook'
         WHERE o.org_id = org
           AND ((o.status IN ('pending', 'failed') AND o.next_attempt_at <= p_now)
                OR (o.status = 'sent' AND o.claimed_until <= p_now))
           AND EXISTS (SELECT 1 FROM consentvault.contact_key ck WHERE ck.org_id = o.org_id AND ck.contact_fp = o.contact_fp)
           AND NOT EXISTS (SELECT 1 FROM consentvault.outbox older
                            WHERE older.org_id = o.org_id AND older.system_id = o.system_id
                              AND older.contact_fp = o.contact_fp AND older.channel = o.channel
                              AND older.purpose = o.purpose AND older.version < o.version
                              AND older.status IN ('pending', 'failed', 'sent'))
         ORDER BY o.priority, o.created_at, o.outbox_id
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
     ORDER BY u.priority, u.created_at, u.outbox_id;
END;
$$;

-- Claim ONE Twenty person group (twenty.md 2.2 step 0, coalescing): every open push of one (system, contact) together, never
-- while another row of that (system, contact) is in flight (rule R7). A group that holds a clear claims only the clear. Stops
-- first, then the oldest. A state push of a contact whose erasure is mid-flight there is superseded here (R1).
CREATE FUNCTION consentvault.sync_claim_person(p_lease_seconds integer)
    RETURNS TABLE (outbox_id uuid, system_id uuid, system_name text, contact_fp text, channel text, purpose text,
                   push_kind text, erasure_id uuid, payload_ct bytea, attempt integer, window_start timestamptz,
                   endpoint text, config jsonb, retry_window_hours integer, wrapped_key bytea, key_version integer)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    p_now timestamptz := clock_timestamp();   -- the database's clock; no caller names it
    org   uuid := consentvault.sync_org(ARRAY['worker:sync']);
    grp   record;
    clear boolean;
BEGIN
    IF p_lease_seconds IS NULL OR p_lease_seconds < 5 OR p_lease_seconds > 3600 OR p_now IS NULL THEN
        RAISE EXCEPTION 'consentvault sync: a person claim needs a lease of 5 to 3600 seconds' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE consentvault.outbox o
       SET status = 'superseded', next_attempt_at = NULL, claimed_until = NULL, finished_at = p_now, superseded_reason = 'erased'
      FROM consentvault.connected_system s
     WHERE o.org_id = org AND s.org_id = o.org_id AND s.system_id = o.system_id AND s.connector = 'twenty'
       AND o.push_kind IN ('state', 'refresh') AND o.status IN ('pending', 'failed')
       AND consentvault.connector_erasure_midflight(org, o.system_id, o.contact_fp);
    SELECT o.system_id AS sid, o.contact_fp AS fp INTO grp
      FROM consentvault.outbox o
      JOIN consentvault.connected_system s
        ON s.org_id = o.org_id AND s.system_id = o.system_id AND s.status = 'active' AND s.connector = 'twenty'
     WHERE o.org_id = org
       AND ((o.status IN ('pending', 'failed') AND o.next_attempt_at <= p_now)
            OR (o.status = 'sent' AND o.claimed_until <= p_now))
       AND EXISTS (SELECT 1 FROM consentvault.contact_key ck WHERE ck.org_id = o.org_id AND ck.contact_fp = o.contact_fp)
       AND NOT EXISTS (SELECT 1 FROM consentvault.outbox busy
                        WHERE busy.org_id = o.org_id AND busy.system_id = o.system_id AND busy.contact_fp = o.contact_fp
                          AND busy.status = 'sent' AND busy.claimed_until > p_now)
     ORDER BY o.priority, o.created_at, o.outbox_id
     LIMIT 1
       FOR UPDATE OF o SKIP LOCKED;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('connector_group:' || org::text || ':' || grp.sid::text || ':' || grp.fp));
    UPDATE consentvault.delivery d SET status = 'failed', error_class = 'timeout', at = p_now
      FROM consentvault.outbox o
     WHERE o.org_id = org AND o.system_id = grp.sid AND o.contact_fp = grp.fp AND o.status = 'sent'
       AND o.claimed_until <= p_now AND d.org_id = o.org_id AND d.outbox_id = o.outbox_id AND d.attempt = o.attempts
       AND d.status = 'sent';
    SELECT EXISTS (SELECT 1 FROM consentvault.outbox o WHERE o.org_id = org AND o.system_id = grp.sid AND o.contact_fp = grp.fp
                      AND o.push_kind = 'clear' AND o.status IN ('pending', 'failed', 'sent')) INTO clear;
    RETURN QUERY
    WITH upd AS (
        UPDATE consentvault.outbox o
           SET status = 'sent', attempts = o.attempts + 1, next_attempt_at = NULL, last_attempt_at = p_now,
               claimed_until = p_now + p_lease_seconds * interval '1 second'
         WHERE o.org_id = org AND o.system_id = grp.sid AND o.contact_fp = grp.fp
           AND ((o.status IN ('pending', 'failed') AND o.next_attempt_at <= p_now)
                OR (o.status = 'sent' AND o.claimed_until <= p_now))
           AND (NOT clear OR o.push_kind = 'clear')
        RETURNING o.*
    ), ins AS (
        INSERT INTO consentvault.delivery (org_id, outbox_id, attempt, status, at)
        SELECT org, u.outbox_id, u.attempts, 'sent', p_now FROM upd u
        RETURNING 1
    )
    SELECT u.outbox_id, u.system_id, s.name, u.contact_fp, u.channel, u.purpose, u.push_kind, u.erasure_id, u.payload_ct,
           u.attempts, u.window_start, s.endpoint, s.config, s.retry_window_hours, ck.wrapped_key, ck.key_version
      FROM upd u
      JOIN consentvault.connected_system s ON s.org_id = u.org_id AND s.system_id = u.system_id
      JOIN consentvault.contact_key ck ON ck.org_id = u.org_id AND ck.contact_fp = u.contact_fp
     ORDER BY u.priority, u.created_at, u.outbox_id;
END;
$$;

-- Extend the claim lease of a delivery's rows and every Person lease it holds to p_seconds from now (twenty.md 2.2, the
-- heartbeat taken before every call). Refused (object_not_in_prerequisite_state, the worker's StaleAttemptError) when any row
-- is no longer the open attempt, so a delivery whose lease was taken over sends nothing more.
CREATE FUNCTION consentvault.sync_extend_lease(p_outbox_ids uuid[], p_attempts integer[], p_seconds integer) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    p_now timestamptz := clock_timestamp();   -- the database's clock; no caller names it
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
    n   integer;
BEGIN
    IF p_seconds IS NULL OR p_seconds < 5 OR p_seconds > 600 OR cardinality(p_outbox_ids) <> cardinality(p_attempts)
       OR cardinality(p_outbox_ids) = 0 THEN
        RAISE EXCEPTION 'consentvault sync: a lease extension needs 5 to 600 seconds and one attempt per row'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE consentvault.outbox o SET claimed_until = p_now + p_seconds * interval '1 second'
      FROM unnest(p_outbox_ids, p_attempts) AS a(oid, att)
     WHERE o.org_id = org AND o.outbox_id = a.oid AND o.status = 'sent' AND o.attempts = a.att AND o.claimed_until > p_now;
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n <> cardinality(p_outbox_ids) THEN
        RAISE EXCEPTION 'consentvault sync: the lease of this delivery was taken over or ran out' USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    UPDATE consentvault.connector_person_lease l SET lease_until = p_now + p_seconds * interval '1 second'
      FROM unnest(p_outbox_ids, p_attempts) AS a(oid, att)
     WHERE l.org_id = org AND l.outbox_id = a.oid AND l.attempt = a.att;
END;
$$;

-- One write in flight per Twenty Person (rule R19, P_person_lease). Taken before the GET, 30 seconds from the take or the last
-- extension. A lease of another delivery is taken over only once its end plus the 15-second call deadline has passed (rule R22),
-- so a call that could still land is never overtaken. False when another delivery holds it.
CREATE FUNCTION consentvault.sync_lease_person(p_system_id uuid, p_person_id_hash text, p_outbox_id uuid, p_attempt integer) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    p_now timestamptz := clock_timestamp();   -- the database's clock; no caller names it
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync']);
    n   integer;
BEGIN
    INSERT INTO consentvault.connector_person_lease (org_id, system_id, person_id_hash, outbox_id, attempt, lease_until)
    VALUES (org, p_system_id, p_person_id_hash, p_outbox_id, p_attempt, p_now + interval '30 seconds')
    ON CONFLICT (org_id, system_id, person_id_hash) DO UPDATE
       SET outbox_id = EXCLUDED.outbox_id, attempt = EXCLUDED.attempt, lease_until = EXCLUDED.lease_until
     WHERE (connector_person_lease.outbox_id = EXCLUDED.outbox_id AND connector_person_lease.attempt = EXCLUDED.attempt)
        OR connector_person_lease.lease_until + interval '15 seconds' <= p_now;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n = 1;
END;
$$;

-- Released only by its holder, after the read-back (no event deletes a lease: P_lease_never_deleted).
CREATE FUNCTION consentvault.sync_release_person(p_system_id uuid, p_person_id_hash text, p_outbox_id uuid) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync'], false);
    n   integer;
BEGIN
    DELETE FROM consentvault.connector_person_lease l
     WHERE l.org_id = org AND l.system_id = p_system_id AND l.person_id_hash = p_person_id_hash AND l.outbox_id = p_outbox_id;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n = 1;
END;
$$;

-- The combined state of a Person's contributing contacts (twenty.md 1.7, rule R16): of the given fingerprints, those with a
-- live key and no erasure mid-flight on this system. Per channel: denied when any is denied on any purpose, else permitted when
-- any is permitted, else none. One row per channel; the Person-level columns repeat on each row. contributors = 0 means the
-- fields are blanked.
CREATE FUNCTION consentvault.sync_person_state(p_system_id uuid, p_contact_fps text[])
    RETURNS TABLE (channel text, state text, contributors integer, as_of_seq bigint, last_check text,
                   last_check_at timestamptz, evidence_record uuid)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org  uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync'], false);
    fps  text[];
    seq  bigint;
    chk  record;
    evid uuid;
BEGIN
    SELECT coalesce(array_agg(DISTINCT f), '{}') INTO fps FROM unnest(coalesce(p_contact_fps, '{}')) f
     WHERE f ~ '^[0-9a-f]{64}$'
       AND EXISTS (SELECT 1 FROM consentvault.contact_key k WHERE k.org_id = org AND k.contact_fp = f)
       AND NOT consentvault.connector_erasure_midflight(org, p_system_id, f);
    SELECT max(e.seq) INTO seq FROM consentvault.event e WHERE e.org_id = org AND e.contact_fp = ANY (fps);
    SELECT d.policy_action AS act, d.evidence_status AS ev, d.at AS at INTO chk FROM consentvault.gate_decision d
     WHERE d.org_id = org AND d.contact_fp = ANY (fps) ORDER BY d.at DESC LIMIT 1;
    RETURN QUERY
    WITH per AS (
        SELECT cp.contact_fp AS fp, cp.channel AS ch, bool_or(NOT cp.allowed AND cp.reason LIKE 'stopped:%') AS den,
               bool_or(cp.allowed) AS perm
          FROM consentvault.current_permission cp
         WHERE cp.org_id = org AND cp.contact_fp = ANY (fps)
         GROUP BY cp.contact_fp, cp.channel
    ), chans AS (
        SELECT unnest(ARRAY['sms', 'voice', 'artificial_voice', 'email']) AS ch
    )
    SELECT c.ch,
           CASE WHEN bool_or(p.den) THEN 'denied' WHEN bool_or(p.perm) THEN 'permitted' ELSE 'none' END,
           cardinality(fps), seq,
           CASE WHEN chk.act IS NOT NULL THEN chk.act WHEN chk.at IS NOT NULL THEN 'hold' ELSE 'none' END,
           chk.at,
           (SELECT r.record_id FROM consentvault.record r
             WHERE r.org_id = org AND r.contact_fp = coalesce(
                   (SELECT p2.fp FROM per p2 WHERE p2.ch = c.ch AND p2.den
                     ORDER BY (SELECT max(e2.seq) FROM consentvault.event e2 WHERE e2.org_id = org AND e2.contact_fp = p2.fp) DESC
                     LIMIT 1),
                   (SELECT e3.contact_fp FROM consentvault.event e3 WHERE e3.org_id = org AND e3.contact_fp = ANY (fps)
                     ORDER BY e3.seq DESC LIMIT 1))
             LIMIT 1)
      FROM chans c LEFT JOIN per p ON p.ch = c.ch
     GROUP BY c.ch
     ORDER BY c.ch;
END;
$$;

-- The pacing bucket (twenty.md 2.3): 80 requests a minute per system, shared by every worker. True when p_n were taken.
CREATE FUNCTION consentvault.sync_rate_take(p_system_id uuid, p_n integer)
    RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    p_now timestamptz := clock_timestamp();   -- the database's clock; no caller names it
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync', 'admin', 'developer']);
    cap CONSTANT double precision := 80;
    b   record;
    t   double precision;
BEGIN
    IF p_n IS NULL OR p_n < 1 OR p_n > 80 THEN
        RAISE EXCEPTION 'consentvault connector: take 1 to 80 requests' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO consentvault.connector_rate (org_id, system_id, tokens, refilled_at) VALUES (org, p_system_id, cap, p_now)
    ON CONFLICT DO NOTHING;
    SELECT r.tokens AS tokens, r.refilled_at AS at INTO b FROM consentvault.connector_rate r
     WHERE r.org_id = org AND r.system_id = p_system_id FOR UPDATE;
    t := least(cap, b.tokens + greatest(0, extract(epoch FROM (p_now - b.at))) * cap / 60.0);
    IF t < p_n THEN
        UPDATE consentvault.connector_rate SET tokens = t, refilled_at = greatest(b.at, p_now)
         WHERE org_id = org AND system_id = p_system_id;
        RETURN false;
    END IF;
    UPDATE consentvault.connector_rate SET tokens = t - p_n, refilled_at = greatest(b.at, p_now)
     WHERE org_id = org AND system_id = p_system_id;
    RETURN true;
END;
$$;

-- Finish a Twenty attempt: like sync_complete, plus the confirmation (twenty.md 2.4) and a retry that never kills a clear by its
-- window while it waits on a soft-deleted Person (that wait is a release, not an attempt). For a clear, acknowledged means the
-- clear was written or nothing holds the data any more.
CREATE FUNCTION consentvault.sync_complete_connector(p_outbox_id uuid, p_attempt integer, p_outcome text, p_http_status integer,
                                                     p_error_class text, p_error_ct bytea, p_backoff_seconds integer,
                                                     p_confirmation text)
    RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org      uuid := consentvault.sync_org(ARRAY['worker:sync']);
    t_now    timestamptz := clock_timestamp();   -- the database's clock: every time this writes is its own
    o        record;
    final    text;
    dstatus  text;
    deadline timestamptz;
    next_at  timestamptz;
BEGIN
    SELECT x.status AS status, x.attempts AS attempts, x.system_id AS system_id, x.push_kind AS kind,
           x.window_start AS window_start, x.last_attempt_at AS started, s.retry_window_hours AS window_hours
      INTO o FROM consentvault.outbox x
      JOIN consentvault.connected_system s ON s.org_id = x.org_id AND s.system_id = x.system_id
     WHERE x.org_id = org AND x.outbox_id = p_outbox_id FOR UPDATE OF x;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: outbox row % is not in the current organisation', p_outbox_id USING ERRCODE = 'no_data_found';
    END IF;
    IF o.status <> 'sent' OR o.attempts <> p_attempt THEN
        RAISE EXCEPTION 'consentvault sync: attempt % of outbox row % is not the open attempt (status %, attempts %)',
            p_attempt, p_outbox_id, o.status, o.attempts USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    IF p_outcome = 'acknowledged' THEN
        final := 'acknowledged'; dstatus := 'acknowledged';
    ELSIF p_outcome = 'dead' THEN
        final := 'dead'; dstatus := 'dead';
    ELSIF p_outcome = 'retry' THEN
        IF p_backoff_seconds IS NULL OR p_backoff_seconds < 1 OR p_backoff_seconds > 3600 THEN
            RAISE EXCEPTION 'consentvault sync: a retry needs a backoff of 1 to 3600 seconds' USING ERRCODE = 'invalid_parameter_value';
        END IF;
        -- the retry window, in hours from the push's first attempt; past it the push is dead, never retried
        deadline := o.window_start + o.window_hours * interval '1 hour';
        IF t_now >= deadline THEN
            final := 'dead'; dstatus := 'dead';
        ELSE
            -- from this push's own start, as stamped by sync_attempt_started, never past the window
            next_at := least(coalesce(o.started, t_now) + p_backoff_seconds * interval '1 second', deadline);
            final := 'failed'; dstatus := 'failed';
        END IF;
    ELSE
        RAISE EXCEPTION 'consentvault sync: unknown outcome %', p_outcome USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_confirmation IS NOT NULL AND final <> 'acknowledged' AND p_confirmation <> 'mismatch' THEN
        RAISE EXCEPTION 'consentvault sync: only an acknowledged push carries confirmation %', p_confirmation
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE consentvault.outbox x
       SET status = final, claimed_until = NULL, last_http_status = p_http_status,
           last_error_class = CASE WHEN final = 'acknowledged' THEN NULL ELSE p_error_class END,
           next_attempt_at = CASE WHEN final = 'failed' THEN next_at ELSE NULL END,
           finished_at = CASE WHEN final IN ('acknowledged', 'dead') THEN t_now ELSE NULL END,
           confirmation = CASE WHEN final = 'acknowledged' THEN p_confirmation END,
           confirmed_at = CASE WHEN final = 'acknowledged' AND p_confirmation IN ('applied', 'cleared', 'not_in_system') THEN t_now END
     WHERE x.org_id = org AND x.outbox_id = p_outbox_id;
    UPDATE consentvault.delivery d
       SET status = dstatus, http_status = p_http_status, error_class = p_error_class, error_ct = p_error_ct, at = t_now
     WHERE d.org_id = org AND d.outbox_id = p_outbox_id AND d.attempt = p_attempt;
    IF final = 'acknowledged' THEN
        UPDATE consentvault.connected_system s SET last_delivery_at = t_now WHERE s.org_id = org AND s.system_id = o.system_id;
    END IF;
    RETURN final;
END;
$$;

-- 8. Links, flags, destroyed markers, activity (worker and receiver) ------------------------------------------------------
CREATE FUNCTION consentvault.connector_links_of(p_system_id uuid, p_contact_fps text[], p_person_id_hash text DEFAULT NULL)
    RETURNS TABLE (person_id_hash text, contact_fp text, person_id_ct bytea, last_seq_written bigint, deleted_since timestamptz,
                   alarm_level smallint, alarm_raised_at timestamptz, alarm_raises integer, confirmed_at timestamptz)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync', 'capture', 'admin'], false);
BEGIN
    RETURN QUERY
    SELECT l.person_id_hash, l.contact_fp, l.person_id_ct, l.last_seq_written, l.deleted_since, l.alarm_level,
           l.alarm_raised_at, l.alarm_raises, l.confirmed_at
      FROM consentvault.connector_link l
     WHERE l.org_id = org AND l.system_id = p_system_id
       AND (p_contact_fps IS NULL OR l.contact_fp = ANY (p_contact_fps))
       AND (p_person_id_hash IS NULL OR l.person_id_hash = p_person_id_hash)
     ORDER BY l.created_at, l.person_id_hash;
END;
$$;

CREATE FUNCTION consentvault.connector_link_put(p_system_id uuid, p_person_id_hash text, p_contact_fp text, p_person_id_ct bytea,
                                                p_seq_written bigint, p_confirmed boolean)
    RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    p_now timestamptz := clock_timestamp();   -- the database's clock; no caller names it
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync']);
BEGIN
    IF NOT EXISTS (SELECT 1 FROM consentvault.contact_key k WHERE k.org_id = org AND k.contact_fp = p_contact_fp) THEN
        RAISE EXCEPTION 'consentvault connector: no link for a contact with no key' USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    INSERT INTO consentvault.connector_link (org_id, system_id, person_id_hash, contact_fp, person_id_ct, last_seq_written,
                                             last_confirmed_seq, confirmed_at)
    VALUES (org, p_system_id, p_person_id_hash, p_contact_fp, p_person_id_ct, p_seq_written,
            CASE WHEN p_confirmed THEN p_seq_written END, CASE WHEN p_confirmed THEN p_now END)
    ON CONFLICT (org_id, system_id, person_id_hash, contact_fp) DO UPDATE
       SET last_seq_written = coalesce(EXCLUDED.last_seq_written, connector_link.last_seq_written),
           last_confirmed_seq = CASE WHEN p_confirmed THEN EXCLUDED.last_seq_written ELSE connector_link.last_confirmed_seq END,
           confirmed_at = CASE WHEN p_confirmed THEN p_now ELSE connector_link.confirmed_at END,
           deleted_since = NULL, alarm_level = 0, alarm_raised_at = NULL, alarm_raises = 0;
END;
$$;

-- A clear met a soft-deleted Person: remember since when (the 7-day and 30-day alarms count from here).
-- A clear met a soft-deleted Person (R31): the wait starts once (deleted_since) and its age decides the alarm, all on the
-- database's clock: the customer's admin alarm from 7 days (168 hours), raised again each 24 hours; the operator's added at 30
-- days (720 hours). Answers the level (0 none, 1, 2) and whether an alarm is due now (and marks it raised when it is), or no
-- row when the link is gone. The connector never deletes the record.
CREATE FUNCTION consentvault.connector_deleted_wait(p_system_id uuid, p_person_id_hash text, p_contact_fp text)
    RETURNS TABLE (level smallint, due boolean, waiting_since timestamptz)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org   uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync'], false);
    t_now timestamptz := clock_timestamp();
    l     record;
    lvl   smallint;
BEGIN
    UPDATE consentvault.connector_link x SET deleted_since = coalesce(x.deleted_since, t_now)
     WHERE x.org_id = org AND x.system_id = p_system_id AND x.person_id_hash = p_person_id_hash AND x.contact_fp = p_contact_fp
    RETURNING x.deleted_since AS since, x.alarm_level AS alevel, x.alarm_raised_at AS raised INTO l;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    lvl := CASE WHEN t_now - interval '720 hours' >= l.since THEN 2 WHEN t_now - interval '168 hours' >= l.since THEN 1 ELSE 0 END;
    level := lvl; waiting_since := l.since;
    due := lvl > 0 AND (l.raised IS NULL OR l.alevel < lvl OR l.raised <= t_now - interval '24 hours');
    IF due THEN
        UPDATE consentvault.connector_link x SET alarm_level = lvl, alarm_raised_at = t_now, alarm_raises = x.alarm_raises + 1
         WHERE x.org_id = org AND x.system_id = p_system_id AND x.person_id_hash = p_person_id_hash AND x.contact_fp = p_contact_fp;
    END IF;
    RETURN NEXT;
END;
$$;


-- person.restored (or a write that reached the Person again): the wait on that Person is over and its alarms close.
CREATE FUNCTION consentvault.connector_person_back(p_system_id uuid, p_person_id_hash text) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync', 'capture'], false);
    n   integer;
BEGIN
    UPDATE consentvault.connector_link l SET deleted_since = NULL, alarm_level = 0, alarm_raised_at = NULL, alarm_raises = 0
     WHERE l.org_id = org AND l.system_id = p_system_id AND l.person_id_hash = p_person_id_hash AND l.deleted_since IS NOT NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    -- a clear waiting on this Person is sent now, not at its next scheduled look
    UPDATE consentvault.outbox o SET next_attempt_at = least(o.next_attempt_at, clock_timestamp())
     WHERE o.org_id = org AND o.system_id = p_system_id AND o.push_kind = 'clear' AND o.status IN ('pending', 'failed')
       AND o.contact_fp IN (SELECT l.contact_fp FROM consentvault.connector_link l
                             WHERE l.org_id = org AND l.system_id = p_system_id AND l.person_id_hash = p_person_id_hash);
    RETURN n;
END;
$$;

-- person.destroyed (twenty.md 3.3, P_destroy_drops_links, P_destroyed_marker): every link and the flag history of that Person go,
-- one destroyed marker is written keyed on its record hash alone, the lease row stays. Answers the contacts whose links went.
CREATE FUNCTION consentvault.connector_destroy(p_system_id uuid, p_person_id_hash text)
    RETURNS text[]
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    p_now timestamptz := clock_timestamp();   -- the database's clock; no caller names it
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync', 'capture'], false);
    gone text[];
BEGIN
    WITH d AS (DELETE FROM consentvault.connector_link l
                WHERE l.org_id = org AND l.system_id = p_system_id AND l.person_id_hash = p_person_id_hash
                RETURNING l.contact_fp)
    SELECT coalesce(array_agg(d.contact_fp), '{}') INTO gone FROM d;
    DELETE FROM consentvault.connector_flag_seen f
     WHERE f.org_id = org AND f.system_id = p_system_id AND f.person_id_hash = p_person_id_hash;
    DELETE FROM consentvault.connector_point_hint p
     WHERE p.org_id = org AND p.system_id = p_system_id AND p.person_id_hash = p_person_id_hash;
    INSERT INTO consentvault.connector_destroyed (org_id, system_id, person_id_hash, destroyed_at)
    VALUES (org, p_system_id, p_person_id_hash, p_now) ON CONFLICT DO NOTHING;
    RETURN gone;
END;
$$;

CREATE FUNCTION consentvault.connector_is_destroyed(p_system_id uuid, p_person_id_hash text) RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync', 'capture'], false);
BEGIN
    RETURN EXISTS (SELECT 1 FROM consentvault.connector_destroyed d
                    WHERE d.org_id = org AND d.system_id = p_system_id AND d.person_id_hash = p_person_id_hash);
END;
$$;

-- Markers are swept after 720 hours (30 days; the sweeper's lane calls this).
CREATE FUNCTION consentvault.connector_sweep_destroyed() RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    p_now timestamptz := clock_timestamp();   -- the database's clock; no caller names it
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
    n   integer;
BEGIN
    DELETE FROM consentvault.connector_destroyed d WHERE d.org_id = org AND d.destroyed_at < p_now - interval '720 hours';
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$;

CREATE FUNCTION consentvault.connector_flag_seen_get(p_system_id uuid, p_person_id_hash text) RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync', 'capture'], false);
    f   boolean;
BEGIN
    SELECT s.flag INTO f FROM consentvault.connector_flag_seen s
     WHERE s.org_id = org AND s.system_id = p_system_id AND s.person_id_hash = p_person_id_hash;
    RETURN f;   -- NULL: no row, never processed (first sight)
END;
$$;

CREATE FUNCTION consentvault.connector_flag_seen_set(p_system_id uuid, p_person_id_hash text, p_flag boolean) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    p_now timestamptz := clock_timestamp();   -- the database's clock; no caller names it
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync', 'capture']);
BEGIN
    INSERT INTO consentvault.connector_flag_seen (org_id, system_id, person_id_hash, flag, updated_at)
    VALUES (org, p_system_id, p_person_id_hash, p_flag, p_now)
    ON CONFLICT (org_id, system_id, person_id_hash) DO UPDATE SET flag = EXCLUDED.flag, updated_at = EXCLUDED.updated_at;
END;
$$;

CREATE FUNCTION consentvault.connector_count(p_system_id uuid, p_name text, p_n bigint DEFAULT 1) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    p_now timestamptz := clock_timestamp();   -- the database's clock; no caller names it
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync', 'capture', 'admin', 'developer'], false);
BEGIN
    IF p_n IS NULL OR p_n < 1 THEN
        RETURN;
    END IF;
    INSERT INTO consentvault.connector_activity (org_id, system_id, day, name, n, last_at)
    VALUES (org, p_system_id, (p_now AT TIME ZONE 'UTC')::date, p_name, p_n, p_now)
    ON CONFLICT (org_id, system_id, day, name) DO UPDATE SET n = connector_activity.n + EXCLUDED.n, last_at = EXCLUDED.last_at;
END;
$$;

-- The activity list (counts only), last p_days days, for admin, developer and compliance viewer.
-- One hit in a rolling window of the database's clock (the last p_window_seconds up to clock_timestamp()), and the number of hits
-- inside that window including this one. The rejected-key and bad-signature alarms read this count, so no process clock decides
-- which hits fall in the window, and no slot edge splits a burst in two. Hits older than the window are removed as they pass, and
-- once the window already holds p_limit hits (the caller's alarm count) no further row is written, so a flood cannot grow the table.
CREATE FUNCTION consentvault.connector_window_hit(p_system_id uuid, p_name text, p_window_seconds integer, p_limit integer) RETURNS bigint
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org   uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync', 'capture', 'admin', 'developer'], false);
    t_now timestamptz := clock_timestamp();
    n     bigint;
BEGIN
    IF p_window_seconds IS NULL OR p_window_seconds < 60 OR p_window_seconds > 86400 OR p_limit IS NULL OR p_limit < 1 OR p_limit > 1000
       OR p_name !~ '^[a-z][a-z0-9_]{0,40}$' THEN
        RAISE EXCEPTION 'consentvault connector: a window count needs a name, a window of 60 to 86400 seconds and a stop count of 1 to 1000'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- two hits at once take turns: the second counts the first's committed row, so neither alarm count is lost to a race
    PERFORM pg_advisory_xact_lock(hashtextextended('cvwindow:' || org::text || ':' || p_system_id::text || ':' || p_name, 0));
    t_now := clock_timestamp();
    DELETE FROM consentvault.connector_window_mark m
     WHERE m.org_id = org AND m.system_id = p_system_id AND m.name = p_name AND m.at <= t_now - make_interval(secs => p_window_seconds);
    SELECT count(*)::bigint INTO n FROM consentvault.connector_window_mark m
     WHERE m.org_id = org AND m.system_id = p_system_id AND m.name = p_name;
    IF n < p_limit THEN
        INSERT INTO consentvault.connector_window_mark (org_id, system_id, name, at) VALUES (org, p_system_id, p_name, t_now);
        n := n + 1;
    END IF;
    RETURN n;
END;
$$;

CREATE FUNCTION consentvault.connector_activity_of(p_system_id uuid, p_since timestamptz)
    RETURNS TABLE (name text, n bigint, last_at timestamptz)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['admin', 'developer', 'proof_read', 'worker:sync', 'capture'], false);
BEGIN
    RETURN QUERY SELECT a.name, sum(a.n)::bigint, max(a.last_at) FROM consentvault.connector_activity a
     WHERE a.org_id = org AND a.system_id = p_system_id AND a.last_at >= p_since GROUP BY a.name ORDER BY a.name;
END;
$$;

CREATE FUNCTION consentvault.connector_set_state(p_system_id uuid, p_state text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync', 'admin', 'developer', 'capture']);
    n   integer;
BEGIN
    IF consentvault.current_token_scopes() = ARRAY['capture'] AND p_state <> 'needs_attention:webhook_failing' THEN
        RAISE EXCEPTION 'consentvault connector: the receiver may only report a failing webhook' USING ERRCODE = 'insufficient_privilege';
    END IF;
    UPDATE consentvault.connected_system SET connector_state = p_state
     WHERE org_id = org AND system_id = p_system_id AND connector_state IS DISTINCT FROM p_state;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n = 1;   -- true on a change: the caller raises connector.state once per change
END;
$$;

-- The Twenty systems the worker serves, with what the reconcile needs.
CREATE FUNCTION consentvault.connector_systems()
    RETURNS TABLE (system_id uuid, name text, status text, endpoint text, config jsonb, connector_state text,
                   reconcile_requested_at timestamptz, watermark timestamptz, last_run_at timestamptz,
                   failures_in_row integer, last_full_scan_at timestamptz, reconcile_due boolean, full_scan_due boolean)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org   uuid := consentvault.sync_org(ARRAY['worker:sync', 'admin', 'developer']);
    t_now timestamptz := clock_timestamp();   -- the database's clock decides what is due (twenty.md 3.5)
BEGIN
    RETURN QUERY
    WITH x AS (
        SELECT s.system_id, s.name, s.status, s.endpoint, s.config, s.connector_state, s.reconcile_requested_at, r.watermark,
               r.last_run_at, coalesce(r.failures_in_row, 0) AS failures_in_row, r.last_full_scan_at,
               -- the system's interval in minutes, 5 to 1440 (15 when unset or not a whole number)
               least(greatest(CASE WHEN jsonb_typeof(s.config -> 'reconcile_interval_minutes') = 'number'
                                        AND (s.config ->> 'reconcile_interval_minutes') ~ '^[0-9]{1,6}$'
                                   THEN (s.config ->> 'reconcile_interval_minutes')::integer ELSE 15 END, 5), 1440) AS minutes
          FROM consentvault.connected_system s
          LEFT JOIN consentvault.connector_reconcile r ON r.org_id = s.org_id AND r.system_id = s.system_id
         WHERE s.org_id = org AND s.connector = 'twenty' AND s.status IN ('active', 'paused'))
    SELECT x.system_id, x.name, x.status, x.endpoint, x.config, x.connector_state, x.reconcile_requested_at, x.watermark,
           x.last_run_at, x.failures_in_row, x.last_full_scan_at,
           (x.reconcile_requested_at IS NOT NULL OR x.last_run_at IS NULL
            OR x.last_run_at <= t_now - x.minutes * interval '1 minute'
            OR x.last_full_scan_at IS NULL OR x.last_full_scan_at <= t_now - interval '24 hours'),
           (x.last_full_scan_at IS NULL OR x.last_full_scan_at <= t_now - interval '24 hours')
      FROM x ORDER BY x.system_id;
END;
$$;

-- A reconcile run's outcome: the watermark advances only on a fully processed page; failures in a row count toward the alarm.
CREATE FUNCTION consentvault.connector_reconcile_done(p_system_id uuid, p_ok boolean, p_watermark timestamptz, p_full boolean) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    p_now timestamptz := clock_timestamp();   -- the database's clock; no caller names it
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync']);
    f   integer;
BEGIN
    INSERT INTO consentvault.connector_reconcile (org_id, system_id) VALUES (org, p_system_id) ON CONFLICT DO NOTHING;
    UPDATE consentvault.connector_reconcile r
       SET watermark = CASE WHEN p_watermark IS NOT NULL AND (r.watermark IS NULL OR p_watermark > r.watermark)
                            THEN p_watermark ELSE r.watermark END,
           last_run_at = p_now,
           last_ok_at = CASE WHEN p_ok THEN p_now ELSE r.last_ok_at END,
           failures_in_row = CASE WHEN p_ok THEN 0 ELSE r.failures_in_row + 1 END,
           last_full_scan_at = CASE WHEN p_ok AND p_full THEN p_now ELSE r.last_full_scan_at END
     WHERE r.org_id = org AND r.system_id = p_system_id
    RETURNING r.failures_in_row INTO f;
    IF p_ok THEN
        UPDATE consentvault.connected_system SET reconcile_requested_at = NULL WHERE org_id = org AND system_id = p_system_id;
    END IF;
    RETURN f;
END;
$$;

-- Is a write of this Person queued or in flight (twenty.md 6.3: an uncovered stop alarms when none is)?
CREATE FUNCTION consentvault.connector_write_pending(p_system_id uuid, p_contact_fps text[]) RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync'], false);
BEGIN
    RETURN EXISTS (SELECT 1 FROM consentvault.outbox o WHERE o.org_id = org AND o.system_id = p_system_id
                      AND o.contact_fp = ANY (p_contact_fps) AND o.status IN ('pending', 'failed', 'sent'));
END;
$$;


-- The contact point of a fingerprint, sealed under its key (the newest event that carries it): the worker opens it with the
-- contact key it already holds for the push, to find the Person in Twenty. Nothing is returned for a contact with no key.
CREATE FUNCTION consentvault.sync_contact_sealed(p_contact_fp text)
    RETURNS TABLE (event_id uuid, contact_kind text, contact_ct bytea)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
BEGIN
    RETURN QUERY
    SELECT e.event_id, e.contact_kind, e.contact_ct FROM consentvault.event e
     WHERE e.org_id = org AND e.contact_fp = p_contact_fp AND e.contact_ct IS NOT NULL
       AND EXISTS (SELECT 1 FROM consentvault.contact_key k WHERE k.org_id = org AND k.contact_fp = p_contact_fp)
     ORDER BY e.seq DESC LIMIT 1;
END;
$$;

-- Of the given fingerprints, those of a contact whose erasure completed and that has no key since (twenty.md 3.7): an import
-- skips each such point, never the Person.
CREATE FUNCTION consentvault.connector_erased_points(p_contact_fps text[]) RETURNS text[]
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'worker:sync', 'admin']);
    out text[];
BEGIN
    SELECT coalesce(array_agg(DISTINCT f), '{}') INTO out FROM unnest(coalesce(p_contact_fps, '{}')) f
     WHERE EXISTS (SELECT 1 FROM consentvault.erasure_request r WHERE r.org_id = org AND r.contact_fp = f AND r.status = 'completed')
       AND NOT EXISTS (SELECT 1 FROM consentvault.contact_key k WHERE k.org_id = org AND k.contact_fp = f);
    RETURN out;
END;
$$;

-- 9. Secrets, receiver, setup and disconnect ---------------------------------------------------------------------------
CREATE FUNCTION consentvault.connector_secret_get(p_system_id uuid, p_purpose text) RETURNS TABLE (wrapped bytea, sealed bytea)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid;
BEGIN
    IF p_purpose = 'hash_key' THEN
        org := consentvault.sync_org(ARRAY['worker:sync', 'capture', 'admin']);
        RETURN QUERY SELECT c.wrapped, c.sealed FROM consentvault.connector_secret c WHERE c.org_id = org AND c.purpose = 'hash_key';
    ELSE
        org := consentvault.connector_org(p_system_id, CASE WHEN p_purpose = 'webhook_secret'
                                                            THEN ARRAY['worker:sync', 'capture', 'admin']
                                                            ELSE ARRAY['worker:sync', 'admin', 'developer'] END);
        RETURN QUERY SELECT c.wrapped, c.sealed FROM consentvault.connector_secret c
         WHERE c.org_id = org AND c.system_id = p_system_id AND c.purpose = p_purpose;
    END IF;
END;
$$;

-- Admin only (twenty.md 1.1): put or replace the API key or webhook secret of a Twenty system; the hash key once per organisation.
CREATE FUNCTION consentvault.connector_secret_put(p_system_id uuid, p_purpose text, p_wrapped bytea, p_sealed bytea) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid;
BEGIN
    IF p_purpose = 'hash_key' THEN
        org := consentvault.sync_org(ARRAY['admin']);
        INSERT INTO consentvault.connector_secret (org_id, system_id, purpose, wrapped, sealed)
        VALUES (org, NULL, 'hash_key', p_wrapped, NULL) ON CONFLICT DO NOTHING;
        RETURN;
    END IF;
    org := consentvault.connector_org(p_system_id, ARRAY['admin']);
    DELETE FROM consentvault.connector_secret c WHERE c.org_id = org AND c.system_id = p_system_id AND c.purpose = p_purpose;
    INSERT INTO consentvault.connector_secret (org_id, system_id, purpose, wrapped, sealed)
    VALUES (org, p_system_id, p_purpose, p_wrapped, p_sealed);
END;
$$;

-- Mint (or re-mint) the receiver id of a Twenty system: the old one is retired, so it answers 404 at once.
CREATE FUNCTION consentvault.connector_receiver_mint(p_system_id uuid, p_receiver_hash text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['admin']);
BEGIN
    UPDATE consentvault.connector_receiver SET retired_at = clock_timestamp()
     WHERE org_id = org AND system_id = p_system_id AND retired_at IS NULL;
    INSERT INTO consentvault.connector_receiver (org_id, receiver_hash, system_id) VALUES (org, p_receiver_hash, p_system_id);
    UPDATE consentvault.connected_system SET config = config || jsonb_build_object('receiver_minted_at', clock_timestamp())
     WHERE org_id = org AND system_id = p_system_id;
END;
$$;

-- Resolve a receiver id before any tenant is entered (owned by the operator role, as resolve_site_key is). Answers nothing for
-- an unknown, retired or disconnected one, so the route answers 404 alike.
CREATE FUNCTION consentvault.sync_receiver_resolve(p_receiver_hash text)
    RETURNS TABLE (org_id uuid, system_id uuid, status text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT r.org_id, r.system_id, s.status
      FROM consentvault.connector_receiver r
      JOIN consentvault.connected_system s ON s.org_id = r.org_id AND s.system_id = r.system_id
     WHERE p_receiver_hash ~ '^[0-9a-f]{64}$' AND r.receiver_hash = p_receiver_hash AND r.retired_at IS NULL
       AND s.connector = 'twenty' AND s.status IN ('active', 'paused');
$$;
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
ALTER FUNCTION consentvault.sync_receiver_resolve(text) OWNER TO consentvault_operator;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;

-- The address of a Twenty system changes only here, with the API key entered again in the same call (twenty.md 1.1): the key is
-- replaced, the receiver re-minted, and the system goes back to connecting until the self-test passes again.
CREATE FUNCTION consentvault.sync_twenty_set_address(p_system_id uuid, p_base_url text, p_wrapped bytea, p_sealed bytea,
                                                     p_receiver_hash text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['admin']);
BEGIN
    IF p_wrapped IS NULL OR p_sealed IS NULL THEN
        RAISE EXCEPTION 'consentvault connector: a new address needs the API key entered again' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM set_config('consentvault.twenty_address_change', p_system_id::text, true);
    UPDATE consentvault.connected_system
       SET endpoint = p_base_url, config = config || jsonb_build_object('base_url', p_base_url),
           connector_state = 'connecting', status = 'paused'
     WHERE org_id = org AND system_id = p_system_id;
    PERFORM set_config('consentvault.twenty_address_change', '', true);
    PERFORM consentvault.connector_secret_put(p_system_id, 'api_key', p_wrapped, p_sealed);
    PERFORM consentvault.connector_receiver_mint(p_system_id, p_receiver_hash);
END;
$$;

-- Disconnect (twenty.md 5.2, admin only, reason required): stops pushes, retires the receiver, destroys the API key and webhook
-- secret, deletes every flag-seen row and window-count row of the system; queued status and refresh pushes become superseded with reason
-- system_disconnected; an open clear is marked dead (an erasure waiting on it holds for an operator, never passes silently).
CREATE FUNCTION consentvault.sync_twenty_disconnect(p_system_id uuid, p_reason text)
    RETURNS TABLE (superseded integer, clears_dead integer)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['admin']);
    a   integer;
    b   integer;
BEGIN
    IF p_reason IS NULL OR length(btrim(p_reason)) NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION 'consentvault connector: a disconnect needs a reason' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE consentvault.outbox o SET status = 'superseded', next_attempt_at = NULL, claimed_until = NULL,
           finished_at = clock_timestamp(), superseded_reason = 'system_disconnected'
     WHERE o.org_id = org AND o.system_id = p_system_id AND o.push_kind IN ('state', 'refresh')
       AND o.status IN ('pending', 'failed', 'sent');
    GET DIAGNOSTICS a = ROW_COUNT;
    UPDATE consentvault.outbox o SET status = 'dead', next_attempt_at = NULL, claimed_until = NULL,
           finished_at = clock_timestamp(), last_error_class = coalesce(o.last_error_class, 'unreachable')
     WHERE o.org_id = org AND o.system_id = p_system_id AND o.push_kind = 'clear' AND o.status IN ('pending', 'failed', 'sent');
    GET DIAGNOSTICS b = ROW_COUNT;
    UPDATE consentvault.connector_receiver SET retired_at = clock_timestamp()
     WHERE org_id = org AND system_id = p_system_id AND retired_at IS NULL;
    DELETE FROM consentvault.connector_secret c WHERE c.org_id = org AND c.system_id = p_system_id;
    DELETE FROM consentvault.connector_flag_seen f WHERE f.org_id = org AND f.system_id = p_system_id;
    DELETE FROM consentvault.connector_point_hint p WHERE p.org_id = org AND p.system_id = p_system_id;
    DELETE FROM consentvault.connector_window_mark w WHERE w.org_id = org AND w.system_id = p_system_id;
    UPDATE consentvault.connected_system SET status = 'disconnected', connector_state = NULL,
           config = config || jsonb_build_object('disconnected_at', clock_timestamp(), 'disconnect_reason', btrim(p_reason))
     WHERE org_id = org AND system_id = p_system_id;
    superseded := a; clears_dead := b;
    RETURN NEXT;
END;
$$;

-- Is this system disconnected with its key destroyed (the one case proceed-without-clear accepts, rule R15)?
CREATE FUNCTION consentvault.connector_waivable(p_system_id uuid) RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin']);
BEGIN
    RETURN EXISTS (SELECT 1 FROM consentvault.connected_system s
                    WHERE s.org_id = org AND s.system_id = p_system_id AND s.connector = 'twenty' AND s.status = 'disconnected')
       AND NOT EXISTS (SELECT 1 FROM consentvault.connector_secret c
                        WHERE c.org_id = org AND c.system_id = p_system_id AND c.purpose = 'api_key');
END;
$$;


-- The erasure lifecycle's changes to a request's Twenty clears (decline, hold placement, waiver), as the operator or an admin:
-- the one writer of those rows outside the worker. Answers how many rows moved.
CREATE FUNCTION consentvault.connector_clear_supersede(p_erasure_id uuid, p_reason text, p_from text[], p_system_id uuid DEFAULT NULL,
                                                       p_mark_held boolean DEFAULT false)
    RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'worker:restore']);
    n   integer;
BEGIN
    IF p_reason NOT IN ('held', 'declined', 'waived', 'erased') THEN
        RAISE EXCEPTION 'consentvault connector: a clear is superseded as held, declined, waived or erased, not %', p_reason
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_reason = 'waived' AND (p_system_id IS NULL OR NOT consentvault.connector_waivable(p_system_id)) THEN
        RAISE EXCEPTION 'consentvault connector: a clear is waived only once its system is disconnected and its key destroyed'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    UPDATE consentvault.outbox o SET status = 'superseded', superseded_reason = p_reason, next_attempt_at = NULL,
           claimed_until = NULL, finished_at = clock_timestamp()
     WHERE o.org_id = org AND o.erasure_id = p_erasure_id AND o.push_kind = 'clear' AND o.status = ANY (p_from)
       AND (p_system_id IS NULL OR o.system_id = p_system_id);
    GET DIAGNOSTICS n = ROW_COUNT;
    IF p_reason = 'held' AND p_mark_held THEN   -- hold placement marks the pending request held (rule R6), so stops reach Twenty
        UPDATE consentvault.erasure_request r
           SET held_by = consentvault.legal_hold_covering(r.contact_fp), held_since = coalesce(r.held_since, clock_timestamp())
         WHERE r.org_id = org AND r.erasure_id = p_erasure_id AND r.status = 'pending_operator_confirmation'
           AND consentvault.legal_hold_covering(r.contact_fp) IS NOT NULL;
    END IF;
    RETURN n;
END;
$$;


-- The pending requests that have a Twenty clear (hold placement marks them held), as the operator or an admin.
CREATE FUNCTION consentvault.connector_requests_with_clear(p_contact_fps text[])
    RETURNS TABLE (erasure_id uuid, contact_fp text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin']);
BEGIN
    RETURN QUERY
    SELECT r.erasure_id, r.contact_fp FROM consentvault.erasure_request r
     WHERE r.org_id = org AND r.status = 'pending_operator_confirmation'
       AND (p_contact_fps IS NULL OR r.contact_fp = ANY (p_contact_fps))
       AND EXISTS (SELECT 1 FROM consentvault.outbox o WHERE o.org_id = r.org_id AND o.erasure_id = r.erasure_id AND o.push_kind = 'clear')
     ORDER BY r.requested_at;
END;
$$;


CREATE FUNCTION consentvault.connector_hint_put(p_system_id uuid, p_person_id_hash text, p_contact_fp text, p_person_id_ct bytea)
    RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['capture', 'worker:sync']);
BEGIN
    INSERT INTO consentvault.connector_point_hint (org_id, system_id, person_id_hash, contact_fp, person_id_ct)
    VALUES (org, p_system_id, p_person_id_hash, p_contact_fp, p_person_id_ct)
    ON CONFLICT (org_id, system_id, person_id_hash, contact_fp) DO UPDATE SET noted_at = clock_timestamp();
END;
$$;

-- The Persons an event named as carrying this point, not yet found by a delivery (a destroyed Person's rows are gone).
CREATE FUNCTION consentvault.connector_hints_of(p_system_id uuid, p_contact_fp text)
    RETURNS TABLE (person_id_hash text, person_id_ct bytea)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['worker:sync'], false);
BEGIN
    RETURN QUERY SELECT p.person_id_hash, p.person_id_ct FROM consentvault.connector_point_hint p
     WHERE p.org_id = org AND p.system_id = p_system_id AND p.contact_fp = p_contact_fp ORDER BY p.noted_at;
END;
$$;


-- The connected systems that take their own signals back (twenty.md 3.6, the documented echo exception: Twenty), live ones only.
-- The capture writer reads it to push a stop a Twenty system reported back to that system, and to queue a Twenty refresh for a
-- ledger event that moved no state (a repeated stop rewrites a record whose stop staff typed over).
CREATE FUNCTION consentvault.sync_echo_targets() RETURNS TABLE (system_id uuid)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
BEGIN
    RETURN QUERY SELECT s.system_id FROM consentvault.connected_system s
     WHERE s.org_id = org AND s.echo_to_source AND s.connector = 'twenty' AND s.status IN ('active', 'paused')
     ORDER BY s.system_id;
END;
$$;

-- 10. Key rotation: the census and the re-wrap learn 'connector_secret' (bodies of 0055 plus that kind) ---------------------
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
                               OR consentvault.sealed_version(release_reason) = p_version)
    UNION ALL
    SELECT 'connector_secret', count(*) FROM consentvault.connector_secret
     WHERE org_id = p_org AND consentvault.wrap_version(wrapped) = p_version;
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
    ELSIF p_kind = 'connector_secret' THEN
        UPDATE consentvault.connector_secret SET wrapped = p_new
         WHERE org_id = org AND secret_id = p_ref AND wrapped = p_old;
    ELSE
        PERFORM set_config('consentvault.rewrap', 'off', true);
        RAISE EXCEPTION 'consentvault re-wrap refused: unknown secret kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('consentvault.rewrap', 'off', true);
    RETURN n = 1;
END;
$$;
GRANT SELECT (org_id, secret_id, wrapped) ON consentvault.connector_secret TO consentvault_console;

-- 11. Grants ------------------------------------------------------------------------------------------------------------
DO $$
DECLARE
    f text;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'connector_org(uuid, text[], boolean)', 'connector_erasure_midflight(uuid, uuid, text)',
        'sync_enqueue_refresh(uuid, uuid, text, bytea)', 'sync_enqueue_clear(uuid, uuid, uuid, bytea)',
        'connector_lifecycle_locked()', 'sync_request_reconcile(uuid)', 'sync_claim_person(integer)',
        'sync_extend_lease(uuid[], integer[], integer)',
        'sync_lease_person(uuid, text, uuid, integer)', 'sync_release_person(uuid, text, uuid)',
        'sync_person_state(uuid, text[])', 'sync_rate_take(uuid, integer)',
        'sync_complete_connector(uuid, integer, text, integer, text, bytea, integer, text)',
        'connector_links_of(uuid, text[], text)', 'connector_link_put(uuid, text, text, bytea, bigint, boolean)',
        'connector_deleted_wait(uuid, text, text)',
        'connector_person_back(uuid, text)', 'connector_destroy(uuid, text)', 'connector_is_destroyed(uuid, text)',
        'connector_sweep_destroyed()', 'connector_flag_seen_get(uuid, text)',
        'connector_flag_seen_set(uuid, text, boolean)', 'connector_count(uuid, text, bigint)', 'connector_window_hit(uuid, text, integer, integer)',
        'connector_activity_of(uuid, timestamptz)', 'connector_set_state(uuid, text)', 'connector_systems()',
        'connector_reconcile_done(uuid, boolean, timestamptz, boolean)', 'connector_write_pending(uuid, text[])',
        'connector_secret_get(uuid, text)', 'connector_secret_put(uuid, text, bytea, bytea)',
        'connector_receiver_mint(uuid, text)', 'sync_receiver_resolve(text)',
        'sync_twenty_set_address(uuid, text, bytea, bytea, text)', 'sync_twenty_disconnect(uuid, text)',
        'connector_waivable(uuid)', 'connected_system_twenty_address_guard()', 'sync_contact_sealed(text)',
        'connector_erased_points(text[])', 'connector_clear_supersede(uuid, text, text[], uuid, boolean)',
        'connector_requests_with_clear(text[])', 'connector_hint_put(uuid, text, text, bytea)',
        'connector_hints_of(uuid, text)', 'sync_echo_targets()'] LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION consentvault.%s FROM PUBLIC', f);
    END LOOP;
END
$$;
GRANT EXECUTE ON FUNCTION
    consentvault.sync_enqueue_refresh(uuid, uuid, text, bytea), consentvault.sync_enqueue_clear(uuid, uuid, uuid, bytea),
    consentvault.connector_lifecycle_locked(), consentvault.sync_request_reconcile(uuid),
    consentvault.sync_rate_take(uuid, integer), consentvault.connector_links_of(uuid, text[], text),
    consentvault.connector_person_back(uuid, text), consentvault.connector_destroy(uuid, text),
    consentvault.connector_is_destroyed(uuid, text), consentvault.connector_flag_seen_get(uuid, text),
    consentvault.connector_flag_seen_set(uuid, text, boolean),
    consentvault.connector_count(uuid, text, bigint), consentvault.connector_window_hit(uuid, text, integer, integer),
    consentvault.connector_activity_of(uuid, timestamptz),
    consentvault.connector_set_state(uuid, text), consentvault.connector_systems(),
    consentvault.connector_secret_get(uuid, text), consentvault.connector_secret_put(uuid, text, bytea, bytea),
    consentvault.connector_receiver_mint(uuid, text), consentvault.sync_receiver_resolve(text),
    consentvault.sync_twenty_set_address(uuid, text, bytea, bytea, text), consentvault.sync_twenty_disconnect(uuid, text),
    consentvault.connector_waivable(uuid), consentvault.connector_erased_points(text[]),
    consentvault.connector_hint_put(uuid, text, text, bytea), consentvault.sync_echo_targets()
    TO consentvault_app;
GRANT EXECUTE ON FUNCTION
    consentvault.sync_enqueue_refresh(uuid, uuid, text, bytea), consentvault.sync_request_reconcile(uuid),
    consentvault.sync_claim_person(integer), consentvault.sync_extend_lease(uuid[], integer[], integer),
    consentvault.sync_lease_person(uuid, text, uuid, integer), consentvault.sync_release_person(uuid, text, uuid),
    consentvault.sync_person_state(uuid, text[]), consentvault.sync_rate_take(uuid, integer),
    consentvault.sync_complete_connector(uuid, integer, text, integer, text, bytea, integer, text),
    consentvault.connector_links_of(uuid, text[], text),
    consentvault.connector_link_put(uuid, text, text, bytea, bigint, boolean),
    consentvault.connector_deleted_wait(uuid, text, text), consentvault.connector_person_back(uuid, text),
    consentvault.connector_destroy(uuid, text), consentvault.connector_is_destroyed(uuid, text),
    consentvault.connector_sweep_destroyed(), consentvault.connector_flag_seen_get(uuid, text),
    consentvault.connector_flag_seen_set(uuid, text, boolean),
    consentvault.connector_count(uuid, text, bigint), consentvault.connector_window_hit(uuid, text, integer, integer),
    consentvault.connector_activity_of(uuid, timestamptz),
    consentvault.connector_set_state(uuid, text), consentvault.connector_systems(),
    consentvault.connector_reconcile_done(uuid, boolean, timestamptz, boolean),
    consentvault.connector_write_pending(uuid, text[]), consentvault.connector_secret_get(uuid, text),
    consentvault.sync_contact_sealed(text), consentvault.connector_erased_points(text[]),
    consentvault.connector_hint_put(uuid, text, text, bytea), consentvault.connector_hints_of(uuid, text)
    TO consentvault_worker;
GRANT EXECUTE ON FUNCTION consentvault.sync_enqueue_clear(uuid, uuid, uuid, bytea), consentvault.connector_lifecycle_locked(),
    consentvault.sync_enqueue_refresh(uuid, uuid, text, bytea), consentvault.connector_waivable(uuid),
    consentvault.connector_clear_supersede(uuid, text, text[], uuid, boolean), consentvault.connector_links_of(uuid, text[], text),
    consentvault.sync_echo_targets()
    TO consentvault_console;
GRANT EXECUTE ON FUNCTION consentvault.connector_clear_supersede(uuid, text, text[], uuid, boolean),
    consentvault.connector_requests_with_clear(text[]) TO consentvault_app, consentvault_console;
