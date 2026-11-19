-- Stop notices: the moment a stop is recorded, the organisation's admins are told (an email, and a pop-up on their next sign-in
-- that stays until each admin acknowledges). ConsentVault only notifies; nothing here acts on a customer's system.
--
--   stop_notice            one row per recorded stop, written in the SAME transaction as the event (the outbox pattern). Holds the
--                          masked contact only (last four digits, or first letter plus domain), sealed under the display key like
--                          record_index.mask_ct and nulled by erase_contact; never the contact point.
--   stop_notice_mail       one row per recipient per stop: the email queue. The worker groups the rows of one recipient that are
--                          within 60 seconds of each other into ONE email.
--   stop_notice_ack        one row per admin per notice, append-only: that admin has seen it. The audit chain carries the who/when.
--   stop_notice_recipient  addresses an admin added beside the admins; admins themselves always receive notices (there is no
--                          switch to turn a notice off, and removing an added address never removes an admin).
-- No runtime role holds a table privilege on the first, third and fourth; they are reached through the owner-rights functions
-- below, which resolve the tenant and the token scope themselves.

ALTER TABLE consentvault.notify_send_log DROP CONSTRAINT notify_send_log_type_check;
ALTER TABLE consentvault.notify_send_log ADD CONSTRAINT notify_send_log_type_check
    CHECK (type IN ('invite', 'security_alert', 'delivery_failure', 'billing_notice', 'stop_notice'));

CREATE TABLE consentvault.stop_notice (
    org_id         uuid NOT NULL REFERENCES consentvault.organization (org_id),
    notice_id      uuid NOT NULL,
    event_id       uuid NOT NULL,
    contact_fp     text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    record_id      uuid,
    masked_ct      bytea,
    channels       text[] NOT NULL CHECK (cardinality(channels) >= 1),
    purposes       text[] NOT NULL CHECK (cardinality(purposes) >= 1),
    changes        jsonb NOT NULL,
    stopped_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, notice_id),
    UNIQUE (org_id, event_id),
    FOREIGN KEY (org_id, event_id) REFERENCES consentvault.event (org_id, event_id)
);
CREATE INDEX stop_notice_created_idx ON consentvault.stop_notice (org_id, created_at, notice_id);

CREATE TABLE consentvault.stop_notice_recipient (
    org_id       uuid NOT NULL REFERENCES consentvault.organization (org_id),
    recipient_id uuid NOT NULL DEFAULT gen_random_uuid(),
    email_norm   text NOT NULL CHECK (length(email_norm) BETWEEN 3 AND 320 AND email_norm = lower(email_norm)),
    added_by     uuid,
    created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    removed_at   timestamptz,
    PRIMARY KEY (org_id, recipient_id)
);
CREATE UNIQUE INDEX stop_notice_recipient_live_idx ON consentvault.stop_notice_recipient (org_id, email_norm) WHERE removed_at IS NULL;

CREATE TABLE consentvault.stop_notice_mail (
    org_id       uuid NOT NULL REFERENCES consentvault.organization (org_id),
    mail_id      uuid NOT NULL DEFAULT gen_random_uuid(),
    notice_id    uuid NOT NULL,
    member_id    uuid,
    recipient_id uuid,
    queued_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    -- pending: queued. sending: claimed by one run (a lease). sent. failed: a send was refused, retried until attempts run out.
    -- unknown: a claimed row whose lease ran out with no answer; it may have been sent, so it is never sent again (an alarm names it).
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'unknown')),
    attempts     integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    claimed_until timestamptz,
    -- the masked contact as text, for the send job, which holds no key: blanked when the email is sent and by erase_contact
    mask_text    text,
    sent_at      timestamptz,
    PRIMARY KEY (org_id, mail_id),
    FOREIGN KEY (org_id, notice_id) REFERENCES consentvault.stop_notice (org_id, notice_id),
    CONSTRAINT stop_notice_mail_one_recipient CHECK ((member_id IS NULL) <> (recipient_id IS NULL)),
    CONSTRAINT stop_notice_mail_sent_has_time CHECK ((status = 'sent') = (sent_at IS NOT NULL)),
    CONSTRAINT stop_notice_mail_sending_has_lease CHECK (status <> 'sending' OR claimed_until IS NOT NULL)
);
CREATE INDEX stop_notice_mail_due_idx ON consentvault.stop_notice_mail (org_id, queued_at) WHERE status IN ('pending', 'sending', 'failed');

CREATE TABLE consentvault.stop_notice_ack (
    org_id          uuid NOT NULL REFERENCES consentvault.organization (org_id),
    notice_id       uuid NOT NULL,
    member_id       uuid NOT NULL,
    acknowledged_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, notice_id, member_id),
    FOREIGN KEY (org_id, notice_id) REFERENCES consentvault.stop_notice (org_id, notice_id)
);
CREATE TRIGGER stop_notice_ack_append_only BEFORE UPDATE OR DELETE ON consentvault.stop_notice_ack
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['stop_notice', 'stop_notice_recipient', 'stop_notice_mail', 'stop_notice_ack'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
        EXECUTE format('REVOKE ALL ON consentvault.%I FROM PUBLIC', t);
    END LOOP;
END
$$;
-- the admin routes manage the added recipients directly (RLS keeps them to their organisation)
GRANT SELECT, INSERT ON consentvault.stop_notice_recipient TO consentvault_app;
GRANT UPDATE (removed_at) ON consentvault.stop_notice_recipient TO consentvault_app;

-- Capture side: called by the code that records an event, in the event's own transaction, inside a savepoint (a failure here
-- never refuses the stop; the caller raises an alarm). One notice, and one queued email per admin and per added recipient. Idempotent
-- on the event. Answers how many emails it queued (NULL when the event already had its notice); the caller alarms on zero.
CREATE FUNCTION consentvault.stop_notice_record(p_notice_id uuid, p_event_id uuid, p_contact_fp text, p_mask_ct bytea,
                                                p_mask_text text, p_channels text[], p_purposes text[], p_changes jsonb,
                                                p_stopped_at timestamptz) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org   uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
    rec   uuid;
    added integer;
    n1    integer;
    n2    integer;
BEGIN
    SELECT r.record_id INTO rec FROM consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND r.erased_at IS NULL;
    INSERT INTO consentvault.stop_notice (org_id, notice_id, event_id, contact_fp, record_id, masked_ct, channels,
                                          purposes, changes, stopped_at)
    VALUES (org, p_notice_id, p_event_id, p_contact_fp, rec, p_mask_ct, p_channels, p_purposes, p_changes, p_stopped_at)
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS added = ROW_COUNT;
    IF added = 0 THEN
        RETURN NULL;
    END IF;
    INSERT INTO consentvault.stop_notice_mail (org_id, notice_id, member_id, mask_text)
    SELECT org, p_notice_id, m.member_id, p_mask_text FROM consentvault.member m
     WHERE m.org_id = org AND m.role = 'admin' AND m.email_norm IS NOT NULL;
    GET DIAGNOSTICS n1 = ROW_COUNT;
    INSERT INTO consentvault.stop_notice_mail (org_id, notice_id, recipient_id, mask_text)
    SELECT org, p_notice_id, r.recipient_id, p_mask_text FROM consentvault.stop_notice_recipient r
     WHERE r.org_id = org AND r.removed_at IS NULL;
    GET DIAGNOSTICS n2 = ROW_COUNT;
    RETURN n1 + n2;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_record(uuid, uuid, text, bytea, text, text[], text[], jsonb, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_record(uuid, uuid, text, bytea, text, text[], text[], jsonb, timestamptz) TO consentvault_app, consentvault_console;
-- the operator console writes an erasure's stop through the same ledger writer, so it calls the same hook

-- Worker side (scope worker:sync). A claim: the queued emails whose recipient's oldest waiting email is at least p_window seconds
-- old (so a burst of stops merges into one email), taken with FOR UPDATE SKIP LOCKED and leased for p_lease seconds, so two
-- overlapping runs never take the same row. Each claim counts as an attempt. A row whose lease ran out with no answer becomes
-- 'unknown' (it may have been sent) and is never sent again; stop_notice_unknown counts them so the caller can alarm.
CREATE FUNCTION consentvault.stop_notice_claim(p_limit integer, p_max_attempts integer, p_window_seconds integer, p_lease_seconds integer)
    RETURNS TABLE (mail_id uuid, notice_id uuid, address text, queued_at timestamptz, attempts integer, org_name text,
                   mask_text text, channels text[], purposes text[], stopped_at timestamptz, record_id uuid)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
BEGIN
    UPDATE consentvault.stop_notice_mail x SET status = 'unknown', claimed_until = NULL
     WHERE x.org_id = org AND x.status = 'sending' AND x.claimed_until < clock_timestamp();
    RETURN QUERY
    WITH waiting AS (
        SELECT q.mail_id AS wid, coalesce(m.email_norm, r.email_norm) AS addr,
               min(q.queued_at) OVER (PARTITION BY coalesce(q.member_id, q.recipient_id)) AS oldest
          FROM consentvault.stop_notice_mail q
          LEFT JOIN consentvault.member m ON m.org_id = q.org_id AND m.member_id = q.member_id
          LEFT JOIN consentvault.stop_notice_recipient r ON r.org_id = q.org_id AND r.recipient_id = q.recipient_id
         WHERE q.org_id = org AND q.status IN ('pending', 'failed') AND q.attempts < p_max_attempts
           AND coalesce(m.email_norm, r.email_norm) IS NOT NULL),
    due AS (
        SELECT w.wid FROM waiting w
         WHERE clock_timestamp() - w.oldest >= make_interval(secs => p_window_seconds)),
    picked AS (
        SELECT q.mail_id AS pid FROM consentvault.stop_notice_mail q
         WHERE q.org_id = org AND q.mail_id IN (SELECT wid FROM due)
         ORDER BY q.queued_at, q.mail_id LIMIT p_limit
         FOR UPDATE SKIP LOCKED),
    took AS (
        UPDATE consentvault.stop_notice_mail q
           SET status = 'sending', attempts = q.attempts + 1,
               claimed_until = clock_timestamp() + make_interval(secs => p_lease_seconds)
         WHERE q.org_id = org AND q.mail_id IN (SELECT pid FROM picked)
        RETURNING q.mail_id, q.notice_id, q.member_id, q.recipient_id, q.queued_at, q.attempts, q.mask_text)
    SELECT t.mail_id, t.notice_id, coalesce(m.email_norm, r.email_norm), t.queued_at, t.attempts,
           (SELECT o.name FROM consentvault.organization o WHERE o.org_id = org),
           t.mask_text, n.channels, n.purposes, n.stopped_at, n.record_id
      FROM took t
      JOIN consentvault.stop_notice n ON n.org_id = org AND n.notice_id = t.notice_id
      LEFT JOIN consentvault.member m ON m.org_id = org AND m.member_id = t.member_id
      LEFT JOIN consentvault.stop_notice_recipient r ON r.org_id = org AND r.recipient_id = t.recipient_id
     ORDER BY t.queued_at, t.mail_id;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_claim(integer, integer, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_claim(integer, integer, integer, integer) TO consentvault_worker;

-- How many emails of the organisation are in 'unknown' (claimed, lease ran out, outcome never recorded).
CREATE FUNCTION consentvault.stop_notice_unknown() RETURNS integer
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
BEGIN
    RETURN (SELECT count(*) FROM consentvault.stop_notice_mail q WHERE q.org_id = org AND q.status = 'unknown');
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_unknown() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_unknown() TO consentvault_worker;

CREATE FUNCTION consentvault.stop_notice_mail_done(p_mail_ids uuid[], p_sent boolean) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
    n   integer;
BEGIN
    UPDATE consentvault.stop_notice_mail q
       SET status = CASE WHEN p_sent THEN 'sent' ELSE 'failed' END, claimed_until = NULL, mask_text = CASE WHEN p_sent THEN NULL ELSE q.mask_text END,
           sent_at = CASE WHEN p_sent THEN clock_timestamp() END
     WHERE q.org_id = org AND q.mail_id = ANY (p_mail_ids) AND q.status = 'sending';
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_mail_done(uuid[], boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_mail_done(uuid[], boolean) TO consentvault_worker;

-- The delivery status of every connected system for the stops named, read from the sync outbox as it stands now: delivered
-- (acknowledged), waiting (queued, in flight or retrying), refused (dead). No rows for a stop when no system is connected.
CREATE FUNCTION consentvault.stop_notice_delivery(p_notice_ids uuid[])
    RETURNS TABLE (notice_id uuid, system_name text, status text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync', 'admin']);
BEGIN
    RETURN QUERY
    SELECT n.notice_id, s.name,
           CASE WHEN bool_or(o.status = 'dead') THEN 'refused'
                WHEN count(o.outbox_id) = 0 OR bool_or(o.status NOT IN ('acknowledged', 'superseded')) THEN 'waiting'
                ELSE 'delivered' END
      FROM consentvault.stop_notice n
      CROSS JOIN consentvault.connected_system s
      LEFT JOIN LATERAL (
            SELECT x.outbox_id, x.status FROM consentvault.outbox x,
                   jsonb_to_recordset(n.changes) AS c(channel text, purpose text, version integer)
             WHERE x.org_id = org AND x.system_id = s.system_id AND x.contact_fp = n.contact_fp
               AND x.channel = c.channel AND x.purpose = c.purpose AND x.version = c.version) o ON true
     WHERE n.org_id = org AND s.org_id = org AND n.notice_id = ANY (p_notice_ids)
     GROUP BY n.notice_id, s.system_id, s.name
     ORDER BY n.notice_id, s.name;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_delivery(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_delivery(uuid[]) TO consentvault_app, consentvault_worker;

-- Portal side (scope admin). The member is the signed-in person, read from the session token, never a parameter.
CREATE FUNCTION consentvault.stop_notice_member() RETURNS uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    cid text;
BEGIN
    SELECT c.credential_id INTO cid FROM consentvault.current_token_claims() c;
    IF cid IS NULL OR cid !~ '^member:[0-9a-fA-F-]{36}$' THEN
        RAISE EXCEPTION 'consentvault stop notice: this call needs a portal session' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN substr(cid, 8)::uuid;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_member() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_member() TO consentvault_app;

-- The signed-in admin's unacknowledged stops, oldest first, at most p_limit: only stops recorded after the admin joined (a new
-- admin is never shown the organisation's history), and a page at a time so the pop-up is always answerable.
CREATE FUNCTION consentvault.stop_notice_unacknowledged(p_limit integer)
    RETURNS TABLE (notice_id uuid, masked_ct bytea, channels text[], purposes text[], stopped_at timestamptz, record_id uuid, total bigint)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin']);
    me  uuid := consentvault.stop_notice_member();
BEGIN
    RETURN QUERY
    WITH mine AS (
        SELECT n.* FROM consentvault.stop_notice n
          JOIN consentvault.member mem ON mem.org_id = n.org_id AND mem.member_id = me
         WHERE n.org_id = org AND n.created_at >= mem.created_at
           AND NOT EXISTS (SELECT 1 FROM consentvault.stop_notice_ack a
                            WHERE a.org_id = org AND a.notice_id = n.notice_id AND a.member_id = me))
    SELECT x.notice_id, x.masked_ct, x.channels, x.purposes, x.stopped_at, x.record_id, (SELECT count(*) FROM mine)
      FROM mine x ORDER BY x.stopped_at, x.notice_id LIMIT p_limit;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_unacknowledged(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_unacknowledged(integer) TO consentvault_app;

CREATE FUNCTION consentvault.stop_notice_acknowledge(p_notice_ids uuid[]) RETURNS uuid[]
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org  uuid := consentvault.sync_org(ARRAY['admin']);
    me   uuid := consentvault.stop_notice_member();
    done uuid[];
BEGIN
    WITH ins AS (
        INSERT INTO consentvault.stop_notice_ack (org_id, notice_id, member_id)
        SELECT org, n.notice_id, me FROM consentvault.stop_notice n
         WHERE n.org_id = org AND n.notice_id = ANY (p_notice_ids)
        ON CONFLICT DO NOTHING RETURNING notice_id)
    SELECT coalesce(array_agg(notice_id ORDER BY notice_id), ARRAY[]::uuid[]) INTO done FROM ins;
    RETURN done;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_acknowledge(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_acknowledge(uuid[]) TO consentvault_app;

-- Erasure: the body of 0112's erase_contact plus the statements marked below (sealed mask and the send queue's text, both blanked).
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
    -- Stop notices: the sealed mask of this contact's stops is blanked in the same transaction, so nothing readable remains.
    UPDATE consentvault.stop_notice SET masked_ct = NULL
     WHERE org_id = org AND contact_fp = p_contact_fp AND masked_ct IS NOT NULL;
    UPDATE consentvault.stop_notice_mail q SET mask_text = NULL
      FROM consentvault.stop_notice sn
     WHERE sn.org_id = org AND sn.contact_fp = p_contact_fp AND q.org_id = sn.org_id AND q.notice_id = sn.notice_id
       AND q.mask_text IS NOT NULL;
    RETURN n > 0;
END;
$$;
