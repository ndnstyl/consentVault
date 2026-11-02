-- Reverses 0017_lifecycle_fixes.sql. Run it as a superuser (or a BYPASSRLS role), in one transaction.
-- Refuses while a ledger commit, an operator access approval or a waiting erasure is recorded: those are evidence of
-- what was erased and who approved access.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regclass('consentvault.erasure_ledger_commit') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0017 refused: 0017 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.erasure_ledger_commit) THEN
        RAISE EXCEPTION 'consentvault down 0017 refused: erasure ledger commits are recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.operator_access_approval) THEN
        RAISE EXCEPTION 'consentvault down 0017 refused: operator access approvals are recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.erasure_request WHERE wait_reason IS NOT NULL) THEN
        RAISE EXCEPTION 'consentvault down 0017 refused: an erasure is waiting';
    END IF;
END
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

DROP FUNCTION consentvault.approve_operator_access(text, text, integer);
DROP TABLE consentvault.operator_access_approval;
DROP FUNCTION consentvault.operator_access_approval_guard();

CREATE OR REPLACE FUNCTION consentvault.operator_access_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.operator_access is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.closed_at IS NOT NULL OR (NEW.org_id, NEW.access_id, NEW.operator_id, NEW.reason, NEW.approved_by_client,
        NEW.emergency, NEW.client_notified_at, NEW.legal_process_id, NEW.opened_at)
       IS DISTINCT FROM (OLD.org_id, OLD.access_id, OLD.operator_id, OLD.reason, OLD.approved_by_client, OLD.emergency,
                         OLD.client_notified_at, OLD.legal_process_id, OLD.opened_at) THEN
        RAISE EXCEPTION 'consentvault.operator_access: an access only closes, once' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER operator_access_initial ON consentvault.operator_access;
DROP FUNCTION consentvault.operator_access_initial();
ALTER TABLE consentvault.operator_access DROP COLUMN approval_id, DROP COLUMN expires_at;

DROP TRIGGER erasure_request_initial_wait ON consentvault.erasure_request;
DROP FUNCTION consentvault.erasure_request_initial_wait();
ALTER TABLE consentvault.erasure_request DROP CONSTRAINT erasure_request_wait_shape;
ALTER TABLE consentvault.erasure_request DROP COLUMN wait_since, DROP COLUMN wait_reason;

DROP TABLE consentvault.erasure_ledger_commit;

COMMIT;
