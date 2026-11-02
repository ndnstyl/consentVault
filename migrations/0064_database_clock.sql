-- The database's clock for every remaining time a caller named that decided something: the generic sync claim (which rows are
-- due, the lease), completion (whether the retry window has closed, when the next attempt is due) and release (when the row is
-- due again); the records call limit and the reveal-volume log (the billing reads are 0065). Each took a time from its caller,
-- so a caller with a skewed or chosen clock could claim early, keep a dead push alive or reopen its own rate window. Each now reads clock_timestamp() and takes no time: a completion passes its backoff step in seconds
-- (1 to 3600), a release its delay in seconds (0 to 3600). The old forms are dropped, so a caller still passing a time is refused
-- (no such function), never silently obeyed.

DROP FUNCTION consentvault.sync_claim(integer, integer, timestamptz);
CREATE FUNCTION consentvault.sync_claim(p_limit integer, p_lease_seconds integer)
    RETURNS TABLE (outbox_id uuid, system_id uuid, system_name text, contact_fp text, channel text, purpose text,
                   version integer, payload_ct bytea, attempt integer, created_at timestamptz, window_start timestamptz,
                   endpoint text, signature text, contact_form text, retry_window_hours integer,
                   credentials_ct bytea, wrapped_key bytea, key_version integer)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    p_now timestamptz := clock_timestamp();   -- the database's clock; no worker names its claim time
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 500 OR p_lease_seconds IS NULL OR p_lease_seconds < 5
       OR p_lease_seconds > 3600 THEN
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
REVOKE ALL ON FUNCTION consentvault.sync_claim(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_claim(integer, integer) TO consentvault_worker;

DROP FUNCTION consentvault.sync_complete(uuid, integer, text, integer, text, bytea, timestamptz, timestamptz);
CREATE FUNCTION consentvault.sync_complete(p_outbox_id uuid, p_attempt integer, p_outcome text, p_http_status integer,
                                           p_error_class text, p_error_ct bytea, p_backoff_seconds integer) RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org      uuid := consentvault.sync_org(ARRAY['worker:sync']);
    o        record;
    newer    boolean;
    final    text;
    dstatus  text;
    p_now    timestamptz := clock_timestamp();   -- the database's clock: every time this writes and decides is its own
    deadline timestamptz;
    next_at  timestamptz;
BEGIN
    SELECT x.status AS status, x.attempts AS attempts, x.system_id AS system_id, x.contact_fp AS fp, x.channel AS ch,
           x.purpose AS pu, x.version AS ver, x.window_start AS window_start, x.last_attempt_at AS started,
           s.retry_window_hours AS window_hours
      INTO o FROM consentvault.outbox x
      JOIN consentvault.connected_system s ON s.org_id = x.org_id AND s.system_id = x.system_id
     WHERE x.org_id = org AND x.outbox_id = p_outbox_id FOR UPDATE OF x;
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
            IF p_backoff_seconds IS NULL OR p_backoff_seconds < 1 OR p_backoff_seconds > 3600 THEN
                RAISE EXCEPTION 'consentvault sync: a retry needs a backoff of 1 to 3600 seconds'
                    USING ERRCODE = 'invalid_parameter_value';
            END IF;
            -- the retry window, in hours from the push's first attempt: past it the push is dead, never retried
            deadline := o.window_start + o.window_hours * interval '1 hour';
            IF p_now >= deadline THEN
                final := 'dead'; dstatus := 'dead';
            ELSE
                -- from this push's own start (sync_attempt_started's stamp), never past the window
                next_at := least(coalesce(o.started, p_now) + p_backoff_seconds * interval '1 second', deadline);
                final := 'failed';
            END IF;
        END IF;
    ELSE
        RAISE EXCEPTION 'consentvault sync: unknown outcome %', p_outcome USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE consentvault.outbox x
       SET status = final, claimed_until = NULL, last_http_status = p_http_status,
           last_error_class = CASE WHEN final = 'acknowledged' THEN NULL ELSE p_error_class END,
           next_attempt_at = CASE WHEN final = 'failed' THEN next_at ELSE NULL END,
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
REVOKE ALL ON FUNCTION consentvault.sync_complete(uuid, integer, text, integer, text, bytea, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_complete(uuid, integer, text, integer, text, bytea, integer) TO consentvault_worker;

DROP FUNCTION consentvault.sync_release(uuid, integer, timestamptz);
CREATE FUNCTION consentvault.sync_release(p_outbox_id uuid, p_attempt integer, p_delay_seconds integer) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
BEGIN
    IF p_delay_seconds IS NULL OR p_delay_seconds < 0 OR p_delay_seconds > 3600 THEN
        RAISE EXCEPTION 'consentvault sync: a release needs a delay of 0 to 3600 seconds' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE consentvault.outbox o
       SET status = 'pending', attempts = o.attempts - 1, claimed_until = NULL, next_attempt_at = clock_timestamp() + p_delay_seconds * interval '1 second'
     WHERE o.org_id = org AND o.outbox_id = p_outbox_id AND o.status = 'sent' AND o.attempts = p_attempt;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: attempt % of outbox row % is not the open attempt', p_attempt, p_outbox_id
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    DELETE FROM consentvault.delivery d WHERE d.org_id = org AND d.outbox_id = p_outbox_id AND d.attempt = p_attempt;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_release(uuid, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_release(uuid, integer, integer) TO consentvault_worker;

DROP FUNCTION consentvault.record_call_take(text, timestamptz, integer, integer);
CREATE FUNCTION consentvault.record_call_take(p_member text, p_limit integer, p_window_seconds integer)
    RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org    uuid := consentvault.sync_org(ARRAY['admin', 'proof_read']);
    win    interval := make_interval(secs => p_window_seconds);
    n      integer;
    oldest timestamptz;
    p_now  timestamptz := clock_timestamp();   -- the database's clock: no caller can reopen its own window
BEGIN
    IF p_member IS NULL OR p_limit < 1 OR p_window_seconds < 1 THEN
        RAISE EXCEPTION 'consentvault records: a call limit needs a member, a limit and a window' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('consentvault.record_call:' || org::text || ':' || p_member));
    DELETE FROM consentvault.record_call c WHERE c.org_id = org AND c.member_id = p_member AND c.at <= p_now - win;
    SELECT count(*), min(c.at) INTO n, oldest FROM consentvault.record_call c
     WHERE c.org_id = org AND c.member_id = p_member AND c.at > p_now - win;
    IF n >= p_limit THEN
        RETURN greatest(1, ceil(extract(epoch FROM (oldest + win - p_now)))::integer);
    END IF;
    INSERT INTO consentvault.record_call (org_id, member_id, at) VALUES (org, p_member, p_now);
    RETURN 0;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_call_take(text, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.record_call_take(text, integer, integer) TO consentvault_app, consentvault_console;

DROP FUNCTION consentvault.record_reveal_note(text, uuid[], timestamptz);
CREATE FUNCTION consentvault.record_reveal_note(p_member text, p_record_ids uuid[])
    RETURNS TABLE (alarm_member text, alarm_count bigint, alarm_window text)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'proof_read']);
    m   bigint;
    o   bigint;
    p_now timestamptz := clock_timestamp();   -- the database's clock: the volume alarms count real time
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('consentvault.reveal_note:' || org::text));
    IF (SELECT count(*) FROM consentvault.record r WHERE r.org_id = org AND r.record_id = ANY (p_record_ids))
       <> (SELECT count(DISTINCT x) FROM unnest(p_record_ids) x) THEN
        RAISE EXCEPTION 'consentvault records: a revealed record is not in the current organisation' USING ERRCODE = 'no_data_found';
    END IF;
    INSERT INTO consentvault.record_reveal_log (org_id, member_id, record_id, at)
    SELECT org, p_member, x, p_now FROM unnest(p_record_ids) x;
    DELETE FROM consentvault.record_reveal_log l WHERE l.org_id = org AND l.at <= p_now - interval '24 hours';
    SELECT count(DISTINCT l.record_id) INTO m FROM consentvault.record_reveal_log l
     WHERE l.org_id = org AND l.member_id = p_member AND l.at > p_now - interval '60 minutes';
    SELECT count(DISTINCT l.record_id) INTO o FROM consentvault.record_reveal_log l
     WHERE l.org_id = org AND l.at > p_now - interval '24 hours';
    IF m > 1000 AND NOT EXISTS (SELECT 1 FROM consentvault.org_alarm a WHERE a.org_id = org AND a.kind = 'reveal_volume'
                                   AND a.cleared_at IS NULL AND a.detail ->> 'member_id' = p_member) THEN
        INSERT INTO consentvault.org_alarm (org_id, kind, detail)
        VALUES (org, 'reveal_volume', jsonb_build_object('member_id', p_member, 'count', m, 'window', '60m'));
        alarm_member := p_member; alarm_count := m; alarm_window := '60m';
        RETURN NEXT;
    END IF;
    IF o > 5000 AND NOT EXISTS (SELECT 1 FROM consentvault.org_alarm a WHERE a.org_id = org AND a.kind = 'reveal_volume'
                                   AND a.cleared_at IS NULL AND a.detail ->> 'member_id' IS NULL) THEN
        INSERT INTO consentvault.org_alarm (org_id, kind, detail)
        VALUES (org, 'reveal_volume', jsonb_build_object('member_id', NULL, 'count', o, 'window', '24h'));
        alarm_member := NULL; alarm_count := o; alarm_window := '24h';
        RETURN NEXT;
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_reveal_note(text, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.record_reveal_note(text, uuid[]) TO consentvault_app, consentvault_console;
