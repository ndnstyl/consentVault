-- Stop notices: the moment a stop is recorded, the organisation's admins are told (an email, and a pop-up on their next sign-in
-- that stays until each admin acknowledges). ConsentVault only notifies; nothing here acts on a customer's system.
--
--   stop_notice            one row per recorded stop, written in the SAME transaction as the event (the outbox pattern). Holds the
--                          masked contact only (last four digits, or first letter plus domain), never the contact point.
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
    masked_contact text NOT NULL CHECK (length(masked_contact) BETWEEN 3 AND 120),
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
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts     integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    sent_at      timestamptz,
    PRIMARY KEY (org_id, mail_id),
    FOREIGN KEY (org_id, notice_id) REFERENCES consentvault.stop_notice (org_id, notice_id),
    CONSTRAINT stop_notice_mail_one_recipient CHECK ((member_id IS NULL) <> (recipient_id IS NULL)),
    CONSTRAINT stop_notice_mail_sent_has_time CHECK ((status = 'sent') = (sent_at IS NOT NULL))
);
CREATE INDEX stop_notice_mail_due_idx ON consentvault.stop_notice_mail (org_id, queued_at) WHERE status <> 'sent';

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

-- Capture side: called by the code that records an event, in the event's own transaction. One notice, and one queued email per
-- admin and per added recipient. Idempotent on the event. Never refuses for want of a recipient: a stop is recorded whatever
-- happens to its notice (an organisation with no admin still shows the pop-up to the next one).
CREATE FUNCTION consentvault.stop_notice_record(p_notice_id uuid, p_event_id uuid, p_contact_fp text, p_masked text,
                                                p_channels text[], p_purposes text[], p_changes jsonb,
                                                p_stopped_at timestamptz) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org   uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
    rec   uuid;
    added integer;
BEGIN
    SELECT r.record_id INTO rec FROM consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND r.erased_at IS NULL;
    INSERT INTO consentvault.stop_notice (org_id, notice_id, event_id, contact_fp, record_id, masked_contact, channels,
                                          purposes, changes, stopped_at)
    VALUES (org, p_notice_id, p_event_id, p_contact_fp, rec, p_masked, p_channels, p_purposes, p_changes, p_stopped_at)
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS added = ROW_COUNT;
    IF added = 0 THEN
        RETURN NULL;
    END IF;
    INSERT INTO consentvault.stop_notice_mail (org_id, notice_id, member_id)
    SELECT org, p_notice_id, m.member_id FROM consentvault.member m
     WHERE m.org_id = org AND m.role = 'admin' AND m.email_norm IS NOT NULL;
    INSERT INTO consentvault.stop_notice_mail (org_id, notice_id, recipient_id)
    SELECT org, p_notice_id, r.recipient_id FROM consentvault.stop_notice_recipient r
     WHERE r.org_id = org AND r.removed_at IS NULL;
    RETURN p_notice_id;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_record(uuid, uuid, text, text, text[], text[], jsonb, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_record(uuid, uuid, text, text, text[], text[], jsonb, timestamptz) TO consentvault_app, consentvault_console;
-- the operator console writes an erasure's stop through the same ledger writer, so it calls the same hook

-- Worker side (scope worker:sync): the queued emails, with the address each goes to and what the email lists.
CREATE FUNCTION consentvault.stop_notice_due(p_limit integer, p_max_attempts integer)
    RETURNS TABLE (mail_id uuid, notice_id uuid, address text, queued_at timestamptz, org_name text, masked_contact text,
                   channels text[], purposes text[], stopped_at timestamptz, record_id uuid)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
BEGIN
    RETURN QUERY
    SELECT q.mail_id, q.notice_id, coalesce(m.email_norm, r.email_norm), q.queued_at,
           (SELECT o.name FROM consentvault.organization o WHERE o.org_id = org),
           n.masked_contact, n.channels, n.purposes, n.stopped_at, n.record_id
      FROM consentvault.stop_notice_mail q
      JOIN consentvault.stop_notice n ON n.org_id = q.org_id AND n.notice_id = q.notice_id
      LEFT JOIN consentvault.member m ON m.org_id = q.org_id AND m.member_id = q.member_id
      LEFT JOIN consentvault.stop_notice_recipient r ON r.org_id = q.org_id AND r.recipient_id = q.recipient_id
     WHERE q.org_id = org AND q.status <> 'sent' AND q.attempts < p_max_attempts
       AND coalesce(m.email_norm, r.email_norm) IS NOT NULL
     ORDER BY q.queued_at, q.mail_id LIMIT p_limit;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_due(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_due(integer, integer) TO consentvault_worker;

CREATE FUNCTION consentvault.stop_notice_mail_done(p_mail_ids uuid[], p_sent boolean) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
    n   integer;
BEGIN
    UPDATE consentvault.stop_notice_mail q
       SET status = CASE WHEN p_sent THEN 'sent' ELSE 'failed' END, attempts = q.attempts + 1,
           sent_at = CASE WHEN p_sent THEN clock_timestamp() END
     WHERE q.org_id = org AND q.mail_id = ANY (p_mail_ids) AND q.status <> 'sent';
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

-- Portal side (scope admin): the stops this admin has not acknowledged, and the acknowledgement.
CREATE FUNCTION consentvault.stop_notice_unacknowledged(p_member uuid)
    RETURNS TABLE (notice_id uuid, masked_contact text, channels text[], purposes text[], stopped_at timestamptz, record_id uuid)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin']);
BEGIN
    RETURN QUERY
    SELECT n.notice_id, n.masked_contact, n.channels, n.purposes, n.stopped_at, n.record_id
      FROM consentvault.stop_notice n
     WHERE n.org_id = org
       AND NOT EXISTS (SELECT 1 FROM consentvault.stop_notice_ack a
                        WHERE a.org_id = org AND a.notice_id = n.notice_id AND a.member_id = p_member)
     ORDER BY n.stopped_at, n.notice_id;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_unacknowledged(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_unacknowledged(uuid) TO consentvault_app;

CREATE FUNCTION consentvault.stop_notice_acknowledge(p_member uuid, p_notice_ids uuid[]) RETURNS uuid[]
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org  uuid := consentvault.sync_org(ARRAY['admin']);
    done uuid[];
BEGIN
    WITH ins AS (
        INSERT INTO consentvault.stop_notice_ack (org_id, notice_id, member_id)
        SELECT org, n.notice_id, p_member FROM consentvault.stop_notice n
         WHERE n.org_id = org AND n.notice_id = ANY (p_notice_ids)
        ON CONFLICT DO NOTHING RETURNING notice_id)
    SELECT coalesce(array_agg(notice_id ORDER BY notice_id), ARRAY[]::uuid[]) INTO done FROM ins;
    RETURN done;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.stop_notice_acknowledge(uuid, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.stop_notice_acknowledge(uuid, uuid[]) TO consentvault_app;
