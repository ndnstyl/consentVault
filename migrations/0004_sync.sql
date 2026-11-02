-- Suppression sync: push every change of a person's consent state to the client's connected systems, and take
-- signals back from them.
--
--   state_version    one row per (org, contact, channel, purpose): the version counter and the state (permitted or
--                    denied) derived from the ledger. A version moves only when the state moves.
--   outbox           one row per (org, system, contact, channel, purpose, version): the push, with its signed body
--                    held as a ciphertext under the contact's data key. Written in the SAME transaction as the event
--                    (transactional outbox), so no event is ever recorded without its pushes queued.
--   delivery         one row per attempt; the receiver's message text is a ciphertext under the contact's key.
--   inbound_signal   every signal a connected system sent and how it was resolved; the external reference is held as a
--                    ciphertext plus a keyed hash (for deduplication).
--   connected_system the client's receivers; the signing credential is a ciphertext under the organisation's key.
--   redrive_run      counters for one re-queue of dead deliveries.
--
-- No runtime role holds a privilege on any of these tables. The runtime role (consentvault_app) and the worker role
-- (consentvault_worker) reach them only through the owner-rights functions below. Every one of those functions
-- resolves its tenant with consentvault.current_org() and filters on it itself (the table policies are a second,
-- independent fence), and refuses a token without the scope the job needs. The worker's reads therefore never touch
-- the evidence tables as the worker: the only personal-data columns it receives are ciphertexts and one wrapped
-- contact key, useless without the organisation's key service.

-- Scope and tenant check shared by every function below. Not granted to any runtime role; only the definer functions
-- (which run as the owner) call it. In single mode a call with no token is the home organisation.
CREATE FUNCTION consentvault.sync_org(p_any_scope text[]) RETURNS uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org    uuid := consentvault.current_org();
    scopes text[];
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault sync: no tenant entered (consentvault.current_org() is NULL)'
            USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    IF coalesce(current_setting('consentvault.org_token', true), '') <> '' THEN
        scopes := consentvault.current_token_scopes();
        IF scopes IS NULL OR NOT (scopes && p_any_scope) THEN
            RAISE EXCEPTION 'consentvault sync: the token holds none of the scopes this call needs (%)', p_any_scope
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;
    RETURN org;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_org(text[]) FROM PUBLIC;

-- Tables -----------------------------------------------------------------------------------------------------------

CREATE TABLE consentvault.connected_system (
    org_id               uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id            uuid NOT NULL DEFAULT gen_random_uuid(),
    name                 text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    kind                 text NOT NULL CHECK (kind IN ('crm', 'dialer', 'sms', 'email', 'ai_agent', 'webhook')),
    connector            text NOT NULL DEFAULT 'generic_webhook' CHECK (connector ~ '^[a-z][a-z0-9_]{0,31}$'),
    config               jsonb NOT NULL DEFAULT '{}'::jsonb,
    endpoint             text NOT NULL CHECK (length(endpoint) <= 2048 AND endpoint ~ '^https://[^[:space:]/?#@]+([/?#][^[:space:]]*)?$'),
    signature            text NOT NULL CHECK (signature IN ('ed25519', 'hmac')),
    contact_form         text NOT NULL CHECK (contact_form IN ('plaintext', 'fingerprint')),
    retry_window_hours   integer NOT NULL DEFAULT 24 CHECK (retry_window_hours BETWEEN 1 AND 168),
    status               text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused')),
    public_key           text,
    credentials_ct       bytea NOT NULL,
    signal_credential_id uuid,
    last_delivery_at     timestamptz,
    last_test            jsonb,
    created_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, system_id),
    UNIQUE (org_id, name),
    FOREIGN KEY (org_id, signal_credential_id) REFERENCES consentvault.credential (org_id, credential_id),
    CONSTRAINT connected_system_public_key_shape CHECK ((signature = 'ed25519') = (public_key IS NOT NULL))
);
CREATE UNIQUE INDEX connected_system_signal_credential_idx
    ON consentvault.connected_system (org_id, signal_credential_id) WHERE signal_credential_id IS NOT NULL;

CREATE TABLE consentvault.state_version (
    org_id         uuid NOT NULL REFERENCES consentvault.organization (org_id),
    contact_fp     text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    channel        text NOT NULL CHECK (channel IN ('voice', 'artificial_voice', 'sms', 'email')),
    purpose        text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 100),
    version        integer NOT NULL CHECK (version >= 1),
    state          text NOT NULL CHECK (state IN ('permitted', 'denied')),
    basis_event_id uuid NOT NULL,
    at             timestamptz NOT NULL,
    advanced_txid  bigint NOT NULL,
    PRIMARY KEY (org_id, contact_fp, channel, purpose),
    FOREIGN KEY (org_id, basis_event_id) REFERENCES consentvault.event (org_id, event_id)
);

CREATE TABLE consentvault.redrive_run (
    org_id       uuid NOT NULL REFERENCES consentvault.organization (org_id),
    redrive_id   uuid NOT NULL DEFAULT gen_random_uuid(),
    system_id    uuid NOT NULL,
    reason       text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
    requested_by text,
    requeued     integer NOT NULL DEFAULT 0 CHECK (requeued >= 0),
    acknowledged integer NOT NULL DEFAULT 0 CHECK (acknowledged >= 0),
    dead_again   integer NOT NULL DEFAULT 0 CHECK (dead_again >= 0),
    status       text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done')),
    started_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at  timestamptz,
    PRIMARY KEY (org_id, redrive_id),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id),
    CONSTRAINT redrive_run_finished CHECK ((status = 'done') = (finished_at IS NOT NULL))
);
-- One running redrive per system (redrive_in_progress).
CREATE UNIQUE INDEX redrive_run_one_running_idx ON consentvault.redrive_run (org_id, system_id) WHERE status = 'running';

CREATE TABLE consentvault.outbox (
    org_id          uuid NOT NULL REFERENCES consentvault.organization (org_id),
    outbox_id       uuid NOT NULL,
    system_id       uuid NOT NULL,
    contact_fp      text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    channel         text NOT NULL CHECK (channel IN ('voice', 'artificial_voice', 'sms', 'email')),
    purpose         text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 100),
    version         integer NOT NULL CHECK (version >= 1),
    payload_ct      bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- the retry window runs from here: creation, or the redrive that re-queued the row
    window_start    timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- pending: queued, never tried. sent: claimed by a worker (in flight). failed: tried, retry scheduled.
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'sent', 'failed', 'acknowledged', 'dead', 'superseded')),
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz,
    claimed_until   timestamptz,
    last_attempt_at timestamptz,
    last_http_status integer,
    last_error_class text CHECK (last_error_class IN ('timeout', 'http_4xx', 'http_5xx', 'signature_rejected', 'unreachable')),
    finished_at     timestamptz,
    alarmed_at      timestamptz,
    redrive_id      uuid,
    PRIMARY KEY (org_id, outbox_id),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id),
    FOREIGN KEY (org_id, redrive_id) REFERENCES consentvault.redrive_run (org_id, redrive_id),
    -- the idempotency key of a push
    UNIQUE (org_id, system_id, contact_fp, channel, purpose, version),
    CONSTRAINT outbox_waiting_has_a_time CHECK (status NOT IN ('pending', 'failed') OR next_attempt_at IS NOT NULL),
    CONSTRAINT outbox_in_flight_has_a_lease CHECK (status <> 'sent' OR claimed_until IS NOT NULL),
    CONSTRAINT outbox_finished_has_an_end CHECK (status NOT IN ('acknowledged', 'dead', 'superseded') OR finished_at IS NOT NULL)
);
CREATE INDEX outbox_due_idx ON consentvault.outbox (org_id, next_attempt_at) WHERE status IN ('pending', 'failed');
CREATE INDEX outbox_lease_idx ON consentvault.outbox (org_id, claimed_until) WHERE status = 'sent';
CREATE INDEX outbox_system_created_idx ON consentvault.outbox (org_id, system_id, created_at DESC, outbox_id DESC);
CREATE INDEX outbox_contact_idx ON consentvault.outbox (org_id, contact_fp, system_id, created_at DESC);
CREATE INDEX outbox_unalarmed_dead_idx ON consentvault.outbox (org_id, system_id) WHERE status = 'dead' AND alarmed_at IS NULL;
CREATE INDEX outbox_redrive_idx ON consentvault.outbox (org_id, redrive_id) WHERE redrive_id IS NOT NULL;

CREATE TABLE consentvault.delivery (
    org_id       uuid NOT NULL,
    outbox_id    uuid NOT NULL,
    attempt      integer NOT NULL CHECK (attempt >= 1),
    status       text NOT NULL CHECK (status IN ('sent', 'acknowledged', 'failed', 'dead')),
    http_status  integer,
    error_class  text CHECK (error_class IN ('timeout', 'http_4xx', 'http_5xx', 'signature_rejected', 'unreachable')),
    error_ct     bytea,
    at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, outbox_id, attempt),
    FOREIGN KEY (org_id, outbox_id) REFERENCES consentvault.outbox (org_id, outbox_id)
);

CREATE TABLE consentvault.inbound_signal (
    org_id          uuid NOT NULL REFERENCES consentvault.organization (org_id),
    signal_id       uuid NOT NULL,
    system_id       uuid NOT NULL,
    contact_fp      text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    channel         text NOT NULL CHECK (channel IN ('voice', 'artificial_voice', 'sms', 'email')),
    purpose         text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 100),
    claimed_state   text NOT NULL CHECK (claimed_state IN ('permitted', 'denied')),
    -- evidence only: signals are judged by arrival order, never by this time
    claimed_at      timestamptz,
    resolution      text NOT NULL CHECK (resolution IN ('applied_as_event', 'no_change', 'ignored_stale', 'conflict_stop_wins')),
    event_id        uuid,
    external_ref_ct bytea NOT NULL,
    -- keyed hash of (system, external reference) under the contact's data key; the deduplication key
    external_ref_mac text NOT NULL CHECK (external_ref_mac ~ '^[0-9a-f]{64}$'),
    received_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, signal_id),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id),
    FOREIGN KEY (org_id, event_id) REFERENCES consentvault.event (org_id, event_id),
    UNIQUE (org_id, system_id, external_ref_mac),
    CONSTRAINT inbound_signal_event_iff_applied CHECK ((resolution = 'applied_as_event') = (event_id IS NOT NULL))
);

-- Row-level security: a second fence behind the functions' own org filters. FORCE binds the owner too. (Policy names
-- end in _sync_tenant: the admin migration enables the same fence on connected_system under its own name.)
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['connected_system', 'state_version', 'redrive_run', 'outbox', 'delivery', 'inbound_signal'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_sync_tenant', t);
        EXECUTE format('REVOKE ALL ON consentvault.%I FROM PUBLIC', t);
    END LOOP;
END
$$;

-- Capture side: called by the code that records an event, inside the capture transaction ----------------------------

-- Derive the new state of every (channel, purpose) the event touches from the ledger (consentvault.current_permission)
-- and advance the version of each key whose state moved. Answers only the keys that moved. Takes the ledger lock of
-- the organisation, so versions of one person are handed out in ledger order.
CREATE FUNCTION consentvault.sync_advance_state(p_event_id uuid, p_contact_fp text)
    RETURNS TABLE (channel text, purpose text, version integer, state text, basis_event_id uuid, reason text, at timestamptz)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org       uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
    ev        record;
    k         record;
    cur       record;
    new_state text;
BEGIN
    SELECT e.channels AS chans, e.purposes AS purps, e.contact_fp AS fp, e.event_type AS etype, e.received_at AS rcv
      INTO ev FROM consentvault.event e WHERE e.org_id = org AND e.event_id = p_event_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: event % is not in the current organisation', p_event_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF ev.fp IS DISTINCT FROM p_contact_fp THEN
        RAISE EXCEPTION 'consentvault sync: event % is not for that contact fingerprint', p_event_id
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(consentvault.ledger_lock_key(org));
    FOR k IN
        SELECT cp.channel AS ch, cp.purpose AS pu, cp.allowed AS al, cp.deciding_event_id AS deciding
          FROM consentvault.current_permission cp
         WHERE cp.org_id = org AND cp.contact_fp = p_contact_fp AND cp.channel = ANY (ev.chans)
           AND (cp.purpose = ANY (ev.purps) OR '*' = ANY (ev.purps))
         ORDER BY cp.channel, cp.purpose
    LOOP
        new_state := CASE WHEN k.al THEN 'permitted' ELSE 'denied' END;
        SELECT sv.version AS v, sv.state AS s INTO cur FROM consentvault.state_version sv
         WHERE sv.org_id = org AND sv.contact_fp = p_contact_fp AND sv.channel = k.ch AND sv.purpose = k.pu
           FOR UPDATE;
        IF NOT FOUND THEN
            version := 1;
            INSERT INTO consentvault.state_version (org_id, contact_fp, channel, purpose, version, state, basis_event_id,
                                                    at, advanced_txid)
            VALUES (org, p_contact_fp, k.ch, k.pu, 1, new_state, coalesce(k.deciding, p_event_id), ev.rcv, txid_current());
        ELSIF cur.s = new_state THEN
            CONTINUE;
        ELSE
            version := cur.v + 1;
            UPDATE consentvault.state_version sv
               SET version = cur.v + 1, state = new_state, basis_event_id = coalesce(k.deciding, p_event_id), at = ev.rcv,
                   advanced_txid = txid_current()
             WHERE sv.org_id = org AND sv.contact_fp = p_contact_fp AND sv.channel = k.ch AND sv.purpose = k.pu;
        END IF;
        channel := k.ch;
        purpose := k.pu;
        state := new_state;
        basis_event_id := coalesce(k.deciding, p_event_id);
        reason := ev.etype;
        at := ev.rcv;
        RETURN NEXT;
    END LOOP;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_advance_state(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_advance_state(uuid, text) TO consentvault_app;

-- The systems a state change goes to (paused ones too: they receive the newest state when resumed; older queued
-- rows are superseded). Only the fields the writer needs to build the body.
CREATE FUNCTION consentvault.sync_targets() RETURNS TABLE (system_id uuid, contact_form text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
BEGIN
    RETURN QUERY
    SELECT s.system_id, s.contact_form FROM consentvault.connected_system s
     WHERE s.org_id = org AND s.status IN ('active', 'paused') ORDER BY s.system_id;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_targets() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_targets() TO consentvault_app;

-- Queue one push. Refused unless the state version it carries was advanced by THIS transaction, so a capture token
-- can queue only what its own event just changed, never an invented state. Queuing version n+1 supersedes older rows
-- of the same key that nobody has started delivering. Answers NULL when that exact push is already queued.
CREATE FUNCTION consentvault.sync_enqueue(p_outbox_id uuid, p_system_id uuid, p_contact_fp text, p_channel text,
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
REVOKE ALL ON FUNCTION consentvault.sync_enqueue(uuid, uuid, text, text, text, integer, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_enqueue(uuid, uuid, text, text, text, integer, bytea) TO consentvault_app;

-- Connected systems: the admin lane registers and edits them (it holds column grants on the table). The binding of a
-- machine credential to the system whose signals it carries is the one write the sync lane owns.

CREATE FUNCTION consentvault.sync_system_bind_credential(p_system_id uuid, p_credential_id uuid) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'developer']);
BEGIN
    PERFORM 1 FROM consentvault.credential c
     WHERE c.org_id = org AND c.credential_id = p_credential_id AND c.revoked_at IS NULL
       AND 'capture' = ANY (c.scope);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: credential % is not a live capture credential of the current organisation',
            p_credential_id USING ERRCODE = 'no_data_found';
    END IF;
    UPDATE consentvault.connected_system s SET signal_credential_id = p_credential_id
     WHERE s.org_id = org AND s.system_id = p_system_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: system % is not in the current organisation', p_system_id
            USING ERRCODE = 'no_data_found';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_system_bind_credential(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_system_bind_credential(uuid, uuid) TO consentvault_app;

-- The system a signal credential belongs to (NULL when the credential is bound to none).
CREATE FUNCTION consentvault.sync_system_of_credential(p_credential_id uuid) RETURNS uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified']);
    sid uuid;
BEGIN
    SELECT s.system_id INTO sid FROM consentvault.connected_system s
     WHERE s.org_id = org AND s.signal_credential_id = p_credential_id;
    RETURN sid;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_system_of_credential(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_system_of_credential(uuid) TO consentvault_app;

-- Inbound signals ---------------------------------------------------------------------------------------------------

-- The ledger's own answer for one key, the authority a signal is judged against: 'denied', 'permitted' or NULL (the
-- ledger holds nothing for this contact, channel and purpose). A stop on all purposes counts against any purpose.
CREATE FUNCTION consentvault.sync_ledger_state(p_contact_fp text, p_channel text, p_purpose text) RETURNS text
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org     uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified']);
    own     boolean;
    star    boolean;
    have_own  boolean := false;
    have_star boolean := false;
BEGIN
    SELECT cp.allowed INTO own FROM consentvault.current_permission cp
     WHERE cp.org_id = org AND cp.contact_fp = p_contact_fp AND cp.channel = p_channel AND cp.purpose = p_purpose;
    have_own := FOUND;
    SELECT cp.allowed INTO star FROM consentvault.current_permission cp
     WHERE cp.org_id = org AND cp.contact_fp = p_contact_fp AND cp.channel = p_channel AND cp.purpose = '*';
    have_star := FOUND;
    IF have_star AND NOT star THEN
        RETURN 'denied';
    END IF;
    IF have_own THEN
        RETURN CASE WHEN own THEN 'permitted' ELSE 'denied' END;
    END IF;
    IF have_star THEN
        RETURN 'permitted';
    END IF;
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_ledger_state(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_ledger_state(text, text, text) TO consentvault_app;

CREATE FUNCTION consentvault.sync_signal_lookup(p_system_id uuid, p_external_ref_mac text)
    RETURNS TABLE (signal_id uuid, resolution text, event_id uuid)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified']);
BEGIN
    RETURN QUERY
    SELECT i.signal_id, i.resolution, i.event_id FROM consentvault.inbound_signal i
     WHERE i.org_id = org AND i.system_id = p_system_id AND i.external_ref_mac = p_external_ref_mac;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_signal_lookup(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_signal_lookup(uuid, text) TO consentvault_app;

CREATE FUNCTION consentvault.sync_signal_record(p_signal_id uuid, p_system_id uuid, p_contact_fp text, p_channel text,
                                                p_purpose text, p_claimed_state text, p_claimed_at timestamptz,
                                                p_resolution text, p_event_id uuid, p_external_ref_ct bytea,
                                                p_external_ref_mac text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified']);
BEGIN
    INSERT INTO consentvault.inbound_signal (org_id, signal_id, system_id, contact_fp, channel, purpose, claimed_state,
                                             claimed_at, resolution, event_id, external_ref_ct, external_ref_mac)
    VALUES (org, p_signal_id, p_system_id, p_contact_fp, p_channel, p_purpose, p_claimed_state, p_claimed_at,
            p_resolution, p_event_id, p_external_ref_ct, p_external_ref_mac);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_signal_record(uuid, uuid, text, text, text, text, timestamptz, text, uuid, bytea, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_signal_record(uuid, uuid, text, text, text, text, timestamptz, text, uuid, bytea, text)
    TO consentvault_app;

-- Worker side: scope worker:sync (consentvault.dispatch_orgs('sync')), one organisation per transaction -------------

-- Claim up to p_limit due pushes and start one attempt on each. A push is due when it is queued or failed and its time
-- has come, or when it is in flight and its lease ran out (a worker died: delivery is at least once). A push never
-- starts while an OLDER push of the same key (org, system, contact, channel, purpose) is queued, failed or in flight,
-- so version n+1 is never delivered before n is acknowledged, dead or superseded, however many workers run. Rows of a
-- person whose contact key is gone (erased) have nothing left to push and are superseded here.
CREATE FUNCTION consentvault.sync_claim(p_limit integer, p_lease_seconds integer,
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
    UPDATE consentvault.outbox o
       SET status = 'superseded', next_attempt_at = NULL, claimed_until = NULL, finished_at = p_now
     WHERE o.org_id = org
       AND (o.status IN ('pending', 'failed') OR (o.status = 'sent' AND o.claimed_until <= p_now))
       AND NOT EXISTS (SELECT 1 FROM consentvault.contact_key ck WHERE ck.org_id = o.org_id AND ck.contact_fp = o.contact_fp);
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
REVOKE ALL ON FUNCTION consentvault.sync_claim(integer, integer, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_claim(integer, integer, timestamptz) TO consentvault_worker;

-- Finish the attempt a worker holds. Outcome: acknowledged, retry (a newer push of the same key makes the old one
-- superseded instead), or dead. An attempt number that is no longer the open one is refused (a slow worker finishing
-- after its lease was taken over).
CREATE FUNCTION consentvault.sync_complete(p_outbox_id uuid, p_attempt integer, p_outcome text, p_http_status integer,
                                           p_error_class text, p_error_ct bytea, p_next_attempt_at timestamptz,
                                           p_now timestamptz DEFAULT clock_timestamp()) RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org      uuid := consentvault.sync_org(ARRAY['worker:sync']);
    o        record;
    newer    boolean;
    final    text;
    dstatus  text;
BEGIN
    SELECT x.status AS status, x.attempts AS attempts, x.system_id AS system_id, x.contact_fp AS fp, x.channel AS ch,
           x.purpose AS pu, x.version AS ver
      INTO o FROM consentvault.outbox x WHERE x.org_id = org AND x.outbox_id = p_outbox_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: outbox row % is not in the current organisation', p_outbox_id
            USING ERRCODE = 'no_data_found';
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
        dstatus := 'failed';
        SELECT EXISTS (SELECT 1 FROM consentvault.outbox n
                        WHERE n.org_id = org AND n.system_id = o.system_id AND n.contact_fp = o.fp AND n.channel = o.ch
                          AND n.purpose = o.pu AND n.version > o.ver) INTO newer;
        IF newer THEN
            final := 'superseded';
        ELSE
            IF p_next_attempt_at IS NULL THEN
                RAISE EXCEPTION 'consentvault sync: a retry needs the time of the next attempt'
                    USING ERRCODE = 'invalid_parameter_value';
            END IF;
            final := 'failed';
        END IF;
    ELSE
        RAISE EXCEPTION 'consentvault sync: unknown outcome %', p_outcome USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE consentvault.outbox x
       SET status = final, claimed_until = NULL, last_http_status = p_http_status,
           last_error_class = CASE WHEN final = 'acknowledged' THEN NULL ELSE p_error_class END,
           next_attempt_at = CASE WHEN final = 'failed' THEN p_next_attempt_at ELSE NULL END,
           finished_at = CASE WHEN final IN ('acknowledged', 'dead', 'superseded') THEN p_now ELSE NULL END
     WHERE x.org_id = org AND x.outbox_id = p_outbox_id;
    UPDATE consentvault.delivery d
       SET status = dstatus, http_status = p_http_status, error_class = p_error_class, error_ct = p_error_ct, at = p_now
     WHERE d.org_id = org AND d.outbox_id = p_outbox_id AND d.attempt = p_attempt;
    IF final = 'acknowledged' THEN
        UPDATE consentvault.connected_system s SET last_delivery_at = p_now
         WHERE s.org_id = org AND s.system_id = o.system_id;
    END IF;
    RETURN final;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_complete(uuid, integer, text, integer, text, bytea, timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_complete(uuid, integer, text, integer, text, bytea, timestamptz, timestamptz)
    TO consentvault_worker;

-- Give back an attempt that never reached the receiver because OUR side failed (the egress door refused the worker's
-- own credential, say): the attempt does not count against the receiver or the retry window.
CREATE FUNCTION consentvault.sync_release(p_outbox_id uuid, p_attempt integer, p_next_attempt_at timestamptz) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
BEGIN
    UPDATE consentvault.outbox o
       SET status = 'pending', attempts = o.attempts - 1, claimed_until = NULL, next_attempt_at = p_next_attempt_at
     WHERE o.org_id = org AND o.outbox_id = p_outbox_id AND o.status = 'sent' AND o.attempts = p_attempt;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: attempt % of outbox row % is not the open attempt', p_attempt, p_outbox_id
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    DELETE FROM consentvault.delivery d WHERE d.org_id = org AND d.outbox_id = p_outbox_id AND d.attempt = p_attempt;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_release(uuid, integer, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_release(uuid, integer, timestamptz) TO consentvault_worker;

-- Dead pushes nobody has been told about, grouped per system and error class (one alarm per group, never one per
-- row), and the acknowledgement that stamps them once the alarm was raised.
CREATE FUNCTION consentvault.sync_dead_groups()
    RETURNS TABLE (system_id uuid, system_name text, error_class text, n bigint, oldest timestamptz, outbox_ids uuid[])
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
BEGIN
    RETURN QUERY
    SELECT o.system_id, s.name, o.last_error_class, count(*), min(o.finished_at), array_agg(o.outbox_id ORDER BY o.outbox_id)
      FROM consentvault.outbox o
      JOIN consentvault.connected_system s ON s.org_id = o.org_id AND s.system_id = o.system_id
     WHERE o.org_id = org AND o.status = 'dead' AND o.alarmed_at IS NULL
     GROUP BY o.system_id, s.name, o.last_error_class
     ORDER BY o.system_id, o.last_error_class;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_dead_groups() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_dead_groups() TO consentvault_worker;

CREATE FUNCTION consentvault.sync_ack_alarms(p_outbox_ids uuid[]) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
    n   integer;
BEGIN
    UPDATE consentvault.outbox o SET alarmed_at = clock_timestamp()
     WHERE o.org_id = org AND o.outbox_id = ANY (p_outbox_ids) AND o.status = 'dead' AND o.alarmed_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_ack_alarms(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_ack_alarms(uuid[]) TO consentvault_worker;

-- Recompute the counters of every running redrive of an organisation; a redrive with nothing left in flight is done.
-- Internal: called by the two functions below, granted to nobody.
CREATE FUNCTION consentvault.sync_redrive_refresh(p_org uuid) RETURNS void
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    UPDATE consentvault.redrive_run r
       SET acknowledged = c.ack, dead_again = c.dead,
           status = CASE WHEN c.remaining = 0 THEN 'done' ELSE 'running' END,
           finished_at = CASE WHEN c.remaining = 0 THEN clock_timestamp() ELSE NULL END
      FROM (SELECT o.redrive_id,
                   count(*) FILTER (WHERE o.status = 'acknowledged') AS ack,
                   count(*) FILTER (WHERE o.status = 'dead') AS dead,
                   count(*) FILTER (WHERE o.status IN ('pending', 'failed', 'sent')) AS remaining
              FROM consentvault.outbox o
             WHERE o.org_id = p_org AND o.redrive_id IS NOT NULL
             GROUP BY o.redrive_id) c
     WHERE r.org_id = p_org AND r.redrive_id = c.redrive_id AND r.status = 'running';
$$;
REVOKE ALL ON FUNCTION consentvault.sync_redrive_refresh(uuid) FROM PUBLIC;

CREATE FUNCTION consentvault.sync_refresh_redrives() RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
BEGIN
    PERFORM consentvault.sync_redrive_refresh(org);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_refresh_redrives() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_refresh_redrives() TO consentvault_worker;

-- Reads and redrive for the portal and the delivery query --------------------------------------------------------------

-- Deliveries of one system, newest first. Fingerprint hint only (first 8 hex characters). The receiver's message text
-- is never returned. Roles admin, developer, compliance viewer (proof_read).
CREATE FUNCTION consentvault.sync_deliveries_of_system(p_system_id uuid, p_status text, p_from timestamptz,
                                                       p_to timestamptz, p_limit integer,
                                                       p_after_created timestamptz, p_after_id uuid)
    RETURNS TABLE (outbox_id uuid, created_at timestamptz, contact_fp_hint text, channel text, purpose text,
                   version integer, status text, attempts integer, last_attempt_at timestamptz,
                   last_http_status integer, last_error_class text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'developer', 'proof_read']);
BEGIN
    PERFORM 1 FROM consentvault.connected_system s WHERE s.org_id = org AND s.system_id = p_system_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: system % is not in the current organisation', p_system_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 201 THEN
        RAISE EXCEPTION 'consentvault sync: limit must be 1 to 201' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN QUERY
    SELECT o.outbox_id, o.created_at, left(o.contact_fp, 8), o.channel, o.purpose, o.version, o.status, o.attempts,
           o.last_attempt_at, o.last_http_status, o.last_error_class
      FROM consentvault.outbox o
     WHERE o.org_id = org AND o.system_id = p_system_id
       AND (p_status IS NULL OR (p_status = 'pending' AND o.status IN ('pending', 'sent', 'failed')) OR o.status = p_status)
       AND (p_from IS NULL OR o.created_at >= p_from) AND (p_to IS NULL OR o.created_at <= p_to)
       AND (p_after_created IS NULL OR (o.created_at, o.outbox_id) < (p_after_created, p_after_id))
     ORDER BY o.created_at DESC, o.outbox_id DESC
     LIMIT p_limit;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_deliveries_of_system(uuid, text, timestamptz, timestamptz, integer, timestamptz, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_deliveries_of_system(uuid, text, timestamptz, timestamptz, integer, timestamptz, uuid)
    TO consentvault_app;

-- Deliveries for one person at one system, newest first. Roles admin and compliance viewer (proof_read); never the
-- developer scope.
CREATE FUNCTION consentvault.sync_deliveries_of_contact(p_contact_fp text, p_system_id uuid, p_limit integer,
                                                        p_after_created timestamptz, p_after_id uuid)
    RETURNS TABLE (outbox_id uuid, created_at timestamptz, channel text, purpose text, version integer, status text,
                   attempts integer, last_http_status integer, last_error_class text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'proof_read']);
BEGIN
    PERFORM 1 FROM consentvault.connected_system s WHERE s.org_id = org AND s.system_id = p_system_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: system % is not in the current organisation', p_system_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 201 THEN
        RAISE EXCEPTION 'consentvault sync: limit must be 1 to 201' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN QUERY
    SELECT o.outbox_id, o.created_at, o.channel, o.purpose, o.version, o.status, o.attempts, o.last_http_status,
           o.last_error_class
      FROM consentvault.outbox o
     WHERE o.org_id = org AND o.system_id = p_system_id AND o.contact_fp = p_contact_fp
       AND (p_after_created IS NULL OR (o.created_at, o.outbox_id) < (p_after_created, p_after_id))
     ORDER BY o.created_at DESC, o.outbox_id DESC
     LIMIT p_limit;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_deliveries_of_contact(text, uuid, integer, timestamptz, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_deliveries_of_contact(text, uuid, integer, timestamptz, uuid)
    TO consentvault_app;

-- Re-queue the dead pushes of one system after it was fixed. Per key only the NEWEST dead row goes back (an older one
-- whose key has a newer row is superseded: only the latest state is ever sent); the retry window restarts. One redrive
-- runs per system at a time (unique_violation on redrive_run_one_running_idx).
CREATE FUNCTION consentvault.sync_redrive_start(p_system_id uuid, p_reason text, p_requested_by text)
    RETURNS TABLE (redrive_id uuid, requeued integer)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'developer']);
    rid uuid := gen_random_uuid();
    n   integer;
BEGIN
    IF p_reason IS NULL OR length(btrim(p_reason)) = 0 OR length(p_reason) > 1000 THEN
        RAISE EXCEPTION 'consentvault sync: a redrive needs a reason of 1 to 1000 characters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM 1 FROM consentvault.connected_system s WHERE s.org_id = org AND s.system_id = p_system_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: system % is not in the current organisation', p_system_id
            USING ERRCODE = 'no_data_found';
    END IF;
    PERFORM consentvault.sync_redrive_refresh(org);
    INSERT INTO consentvault.redrive_run (org_id, redrive_id, system_id, reason, requested_by)
    VALUES (org, rid, p_system_id, p_reason, p_requested_by);
    UPDATE consentvault.outbox o
       SET status = 'superseded', finished_at = clock_timestamp()
     WHERE o.org_id = org AND o.system_id = p_system_id AND o.status = 'dead'
       AND EXISTS (SELECT 1 FROM consentvault.outbox n
                    WHERE n.org_id = o.org_id AND n.system_id = o.system_id AND n.contact_fp = o.contact_fp
                      AND n.channel = o.channel AND n.purpose = o.purpose AND n.version > o.version);
    UPDATE consentvault.outbox o
       SET status = 'pending', next_attempt_at = clock_timestamp(), window_start = clock_timestamp(),
           finished_at = NULL, alarmed_at = NULL, claimed_until = NULL, redrive_id = rid
     WHERE o.org_id = org AND o.system_id = p_system_id AND o.status = 'dead';
    GET DIAGNOSTICS n = ROW_COUNT;
    UPDATE consentvault.redrive_run r
       SET requeued = n, status = CASE WHEN n = 0 THEN 'done' ELSE 'running' END,
           finished_at = CASE WHEN n = 0 THEN clock_timestamp() ELSE NULL END
     WHERE r.org_id = org AND r.redrive_id = rid;
    redrive_id := rid;
    requeued := n;
    RETURN NEXT;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_redrive_start(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_redrive_start(uuid, text, text) TO consentvault_app;

CREATE FUNCTION consentvault.sync_redrive_status(p_redrive_id uuid)
    RETURNS TABLE (redrive_id uuid, system_id uuid, status text, requeued integer, acknowledged integer,
                   dead_again integer, remaining integer, started_at timestamptz, finished_at timestamptz)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'developer']);
BEGIN
    PERFORM consentvault.sync_redrive_refresh(org);
    RETURN QUERY
    SELECT r.redrive_id, r.system_id, r.status, r.requeued, r.acknowledged, r.dead_again,
           (SELECT count(*)::integer FROM consentvault.outbox o
             WHERE o.org_id = r.org_id AND o.redrive_id = r.redrive_id AND o.status IN ('pending', 'failed', 'sent')),
           r.started_at, r.finished_at
      FROM consentvault.redrive_run r WHERE r.org_id = org AND r.redrive_id = p_redrive_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: redrive % is not in the current organisation', p_redrive_id
            USING ERRCODE = 'no_data_found';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_redrive_status(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_redrive_status(uuid) TO consentvault_app;
