-- Lifecycle fixes after the third adversarial review (erasure, restore, legal process, operator access).
--
-- 1. Two-phase erasure ledger. An erasure writes an intent entry to the lifecycle ledger before the key delete, and a
--    commit entry once its transaction has committed. erasure_ledger_commit is the database's memory of which commits
--    are in the ledger, so the sweep that writes them never misses one and never needs to read the ledger.
-- 2. An erasure waits, as a visible state on the request (wait_reason, wait_since), until every push for the person is
--    delivered or dead (pending_suppression_delivery), or, after a restore, until an operator re-confirms an intent the
--    ledger holds without a commit (uncommitted_ledger_intent).
-- 3. sync_claim raises an alarm row for every push it supersedes because the contact key is gone.
-- 4. Operator access. Each access record expires (at most 12 hours; 4 by default in the code). A customer's approval
--    is a row the approving admin writes in their own session (approve_operator_access reads the member from the
--    verified token), used once, by the operator it names, within 24 hours. A typed member id approves nothing.
--
-- No column of seal, chain_head, contact_log or review changes. New tables start under forced row security.

-- 1. Two-phase erasure ledger -------------------------------------------------------------------------------------------
CREATE TABLE consentvault.erasure_ledger_commit (
    org_id       uuid NOT NULL REFERENCES consentvault.organization (org_id),
    erasure_id   uuid NOT NULL,
    intent_seq   bigint NOT NULL CHECK (intent_seq >= 1),
    commit_seq   bigint NOT NULL CHECK (commit_seq > intent_seq),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, erasure_id)
);
CREATE TRIGGER erasure_ledger_commit_no_change BEFORE UPDATE OR DELETE ON consentvault.erasure_ledger_commit
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER erasure_ledger_commit_no_truncate BEFORE TRUNCATE ON consentvault.erasure_ledger_commit
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- 2. Erasure waits ------------------------------------------------------------------------------------------------------
ALTER TABLE consentvault.erasure_request
    ADD COLUMN wait_reason text CHECK (wait_reason IS NULL
                                       OR wait_reason IN ('pending_suppression_delivery', 'uncommitted_ledger_intent')),
    ADD COLUMN wait_since timestamptz;
ALTER TABLE consentvault.erasure_request ADD CONSTRAINT erasure_request_wait_shape
    CHECK ((wait_reason IS NULL) = (wait_since IS NULL) AND (wait_reason IS NULL OR status = 'pending_operator_confirmation'));

CREATE FUNCTION consentvault.erasure_request_initial_wait() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.wait_reason IS NOT NULL OR NEW.wait_since IS NOT NULL THEN
        RAISE EXCEPTION 'consentvault.erasure_request: a new request starts without a wait'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER erasure_request_initial_wait BEFORE INSERT ON consentvault.erasure_request
    FOR EACH ROW EXECUTE FUNCTION consentvault.erasure_request_initial_wait();

-- 4. Operator access ----------------------------------------------------------------------------------------------------
-- A record opened before this migration has no expiry: it reads as expired (the code compares expires_at > now).
ALTER TABLE consentvault.operator_access
    ADD COLUMN expires_at  timestamptz,
    ADD COLUMN approval_id uuid;

CREATE FUNCTION consentvault.operator_access_initial() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.expires_at IS NULL OR NEW.expires_at <= NEW.opened_at OR NEW.expires_at > NEW.opened_at + interval '12 hours'
       OR NEW.closed_at IS NOT NULL OR (NOT NEW.emergency AND NEW.approval_id IS NULL)
       OR (NEW.emergency AND NEW.approval_id IS NOT NULL) THEN
        RAISE EXCEPTION 'consentvault.operator_access: an access opens with an expiry within 12 hours and either a customer approval or an emergency notice'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER operator_access_initial BEFORE INSERT ON consentvault.operator_access
    FOR EACH ROW EXECUTE FUNCTION consentvault.operator_access_initial();

CREATE OR REPLACE FUNCTION consentvault.operator_access_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.operator_access is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.closed_at IS NOT NULL OR (NEW.org_id, NEW.access_id, NEW.operator_id, NEW.reason, NEW.approved_by_client,
        NEW.emergency, NEW.client_notified_at, NEW.legal_process_id, NEW.opened_at, NEW.expires_at, NEW.approval_id)
       IS DISTINCT FROM (OLD.org_id, OLD.access_id, OLD.operator_id, OLD.reason, OLD.approved_by_client, OLD.emergency,
                         OLD.client_notified_at, OLD.legal_process_id, OLD.opened_at, OLD.expires_at, OLD.approval_id) THEN
        RAISE EXCEPTION 'consentvault.operator_access: an access only closes, once' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE consentvault.operator_access_approval (
    org_id         uuid NOT NULL REFERENCES consentvault.organization (org_id),
    approval_id    uuid NOT NULL DEFAULT gen_random_uuid(),
    operator_id    text NOT NULL CHECK (length(operator_id) BETWEEN 1 AND 200),
    reason         text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    approved_by    uuid NOT NULL,
    approved_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at     timestamptz NOT NULL,
    access_minutes integer NOT NULL CHECK (access_minutes BETWEEN 15 AND 240),
    used_at        timestamptz,
    access_id      uuid,
    PRIMARY KEY (org_id, approval_id),
    CONSTRAINT operator_access_approval_use_shape CHECK ((used_at IS NULL) = (access_id IS NULL)),
    CONSTRAINT operator_access_approval_window CHECK (expires_at > approved_at
                                                      AND expires_at <= approved_at + interval '24 hours')
);
CREATE FUNCTION consentvault.operator_access_approval_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.operator_access_approval is a record: DELETE refused'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.used_at IS NOT NULL OR NEW.used_at IS NULL
       OR (NEW.org_id, NEW.approval_id, NEW.operator_id, NEW.reason, NEW.approved_by, NEW.approved_at, NEW.expires_at,
           NEW.access_minutes)
          IS DISTINCT FROM (OLD.org_id, OLD.approval_id, OLD.operator_id, OLD.reason, OLD.approved_by, OLD.approved_at,
                            OLD.expires_at, OLD.access_minutes) THEN
        RAISE EXCEPTION 'consentvault.operator_access_approval: an approval is only used, once'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER operator_access_approval_guard BEFORE UPDATE OR DELETE ON consentvault.operator_access_approval
    FOR EACH ROW EXECUTE FUNCTION consentvault.operator_access_approval_guard();
CREATE TRIGGER operator_access_approval_no_truncate BEFORE TRUNCATE ON consentvault.operator_access_approval
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- The approving admin's own action. The approver is the member the verified tenant token names, never an argument.
CREATE FUNCTION consentvault.approve_operator_access(p_operator_id text, p_reason text, p_access_minutes integer)
    RETURNS TABLE (approval_id uuid, expires_at timestamptz, approved_by uuid)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c   record;
    mid uuid;
    r   text;
BEGIN
    SELECT * INTO c FROM consentvault.current_token_claims();
    IF NOT FOUND OR c.org_id IS NULL OR c.org_id IS DISTINCT FROM consentvault.current_org()
       OR c.credential_id IS NULL OR left(c.credential_id, 7) <> 'member:' THEN
        RAISE EXCEPTION 'consentvault operator access approval refused: no portal member session is entered'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    BEGIN
        mid := substr(c.credential_id, 8)::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'consentvault operator access approval refused: the session names no member'
            USING ERRCODE = 'insufficient_privilege';
    END;
    SELECT m.role INTO r FROM consentvault.member m WHERE m.org_id = c.org_id AND m.member_id = mid;
    IF r IS DISTINCT FROM 'admin' OR NOT ('admin' = ANY (c.scopes)) THEN
        RAISE EXCEPTION 'consentvault operator access approval refused: the session is not an admin of the organization'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN QUERY
    INSERT INTO consentvault.operator_access_approval (org_id, operator_id, reason, approved_by, expires_at, access_minutes)
    VALUES (c.org_id, p_operator_id, p_reason, mid, clock_timestamp() + interval '24 hours', p_access_minutes)
    RETURNING approval_id, expires_at, approved_by;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.approve_operator_access(text, text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.approve_operator_access(text, text, integer) TO consentvault_app;

-- Row-level security for the new tables; the tenant reads its own approvals, writes none directly.
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['erasure_ledger_commit', 'operator_access_approval'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
        EXECUTE format('REVOKE ALL ON consentvault.%I FROM PUBLIC', t);
    END LOOP;
END
$$;
GRANT SELECT ON consentvault.operator_access_approval TO consentvault_app;
-- ids and sequence numbers only: a hold placed in the portal reads it for the ledger's next slot (erasure.ledger_hint)
GRANT SELECT ON consentvault.erasure_ledger_commit TO consentvault_app;

-- 3. sync_claim: an alarm for every push superseded because its contact key is gone --------------------------------------
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
