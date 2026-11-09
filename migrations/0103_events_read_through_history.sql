-- Pure projection, items 20, 22, 23, 24, 25, 26: the SQL that read the frozen event table read one view of every event of an organisation, the
-- frozen ones and the history rows of the posts that came after the cutover (ranked after the last frozen event, so the order of an
-- organisation's events stays one sequence). The functions keep their names, arguments and grants.
CREATE VIEW consentvault.post_history_all_events WITH (security_invoker = true) AS
SELECT e.org_id, e.event_id, e.seq, e.seq AS chain_seq, e.contact_fp, e.contact_kind, e.contact_norm, e.contact_ct, e.contact_commit,
       e.subject_fp, e.source_id, e.brand_ids, e.channels, e.purposes, e.event_type, e.received_at, e.source, e.recorded_by, e.row_hash,
       e.prev_hash, e.origin, e.method, e.disclosure_sha256, e.captured_at
  FROM consentvault.event e
UNION ALL
SELECT h.org_id, h.event_id,
       coalesce((SELECT max(f.seq) FROM consentvault.event f WHERE f.org_id = h.org_id), 0) + h.seq, h.seq, h.contact_fp, h.contact_kind,
       NULL::text, h.contact_ct, NULL::text, NULL::text, h.source_id, h.brand_ids, h.channels, h.purposes, h.event_type, h.received_at,
       NULL::text, NULL::text, h.row_hash, h.prev_hash, h.origin, h.method, h.disclosure_sha256, h.arrival_at
  FROM consentvault.history_events h;
GRANT SELECT ON consentvault.post_history_all_events TO consentvault_app, consentvault_worker, consentvault_console, consentvault_integrity,
    consentvault_isolation_self_test;

-- A sync state may cite a history event as its basis: the key to the frozen table is replaced by a check against the view.
ALTER TABLE consentvault.state_version DROP CONSTRAINT state_version_org_id_basis_event_id_fkey;
CREATE FUNCTION consentvault.state_version_basis_check() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM consentvault.post_history_all_events a WHERE a.org_id OPERATOR(pg_catalog.=) NEW.org_id
                    AND a.event_id OPERATOR(pg_catalog.=) NEW.basis_event_id) THEN
        RAISE EXCEPTION 'consentvault sync: the basis event is neither an event nor a history row of this organisation' USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.state_version_basis_check() FROM PUBLIC;
CREATE TRIGGER state_version_basis_check BEFORE INSERT OR UPDATE OF basis_event_id ON consentvault.state_version
    FOR EACH ROW EXECUTE FUNCTION consentvault.state_version_basis_check();

CREATE OR REPLACE FUNCTION consentvault.sync_advance_state(p_event_id uuid, p_contact_fp text)
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
      INTO ev FROM consentvault.post_history_all_events e WHERE e.org_id = org AND e.event_id = p_event_id;
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
CREATE OR REPLACE FUNCTION consentvault.sync_contact_sealed(p_contact_fp text)
    RETURNS TABLE (event_id uuid, contact_kind text, contact_ct bytea)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
BEGIN
    RETURN QUERY
    SELECT e.event_id, e.contact_kind, e.contact_ct FROM consentvault.post_history_all_events e
     WHERE e.org_id = org AND e.contact_fp = p_contact_fp AND e.contact_ct IS NOT NULL
       AND EXISTS (SELECT 1 FROM consentvault.contact_key k WHERE k.org_id = org AND k.contact_fp = p_contact_fp)
     ORDER BY e.seq DESC LIMIT 1;
END;
$$;
CREATE OR REPLACE FUNCTION consentvault.sync_person_state(p_system_id uuid, p_contact_fps text[])
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
    SELECT max(e.seq) INTO seq FROM consentvault.post_history_all_events e WHERE e.org_id = org AND e.contact_fp = ANY (fps);
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
                     ORDER BY (SELECT max(e2.seq) FROM consentvault.post_history_all_events e2 WHERE e2.org_id = org AND e2.contact_fp = p2.fp) DESC
                     LIMIT 1),
                   (SELECT e3.contact_fp FROM consentvault.post_history_all_events e3 WHERE e3.org_id = org AND e3.contact_fp = ANY (fps)
                     ORDER BY e3.seq DESC LIMIT 1))
             LIMIT 1)
      FROM chans c LEFT JOIN per p ON p.ch = c.ch
     GROUP BY c.ch
     ORDER BY c.ch;
END;
$$;
CREATE OR REPLACE FUNCTION consentvault.record_upsert(p_event_id uuid, p_contact_fp text, p_contact_kind text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
    ev  record;
    rid uuid;
BEGIN
    SELECT e.contact_fp AS fp, e.contact_kind AS kind, e.seq AS sq, e.received_at AS rcv
      INTO ev FROM consentvault.post_history_all_events e WHERE e.org_id = org AND e.event_id = p_event_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: event % is not in the current organisation', p_event_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF ev.fp IS DISTINCT FROM p_contact_fp OR ev.kind IS DISTINCT FROM p_contact_kind THEN
        RAISE EXCEPTION 'consentvault records: event % is not for that contact fingerprint and kind', p_event_id
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(consentvault.ledger_lock_key(org));
    SELECT r.record_id INTO rid FROM consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND r.erased_at IS NULL;
    IF NOT FOUND THEN
        INSERT INTO consentvault.record (org_id, contact_fp, contact_kind, first_recorded_at, first_seq)
        VALUES (org, p_contact_fp, p_contact_kind, ev.rcv, ev.sq) RETURNING record_id INTO rid;
    END IF;
    RETURN rid;
END;
$$;
CREATE OR REPLACE FUNCTION consentvault.record_index_derive(p_org uuid, p_record_id uuid, p_mask_ct bytea, p_default_subject_fp text)
    RETURNS void
    LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r        record;
    nxt      bigint;
    cell_json jsonb;
    stopped  boolean;
    stop_at  timestamptz;
    last_at  timestamptz;
    subj     text;
    first_src uuid;
    srcs     uuid[];
    brs      uuid[];
    trial    boolean;
    dflt     text;
BEGIN
    SELECT rc.* INTO r FROM consentvault.record rc WHERE rc.org_id = p_org AND rc.record_id = p_record_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: record % is not in the current organisation', p_record_id
            USING ERRCODE = 'no_data_found';
    END IF;
    SELECT min(n.first_seq) INTO nxt FROM consentvault.record n
     WHERE n.org_id = p_org AND n.contact_fp = r.contact_fp AND n.first_seq > r.first_seq;

    WITH cp AS (
        SELECT c.channel, c.purpose, c.allowed, c.reason
          FROM consentvault.current_permission c WHERE c.org_id = p_org AND c.contact_fp = r.contact_fp
    ), cells AS (
        SELECT ch.channel, pu.purpose,
               CASE WHEN own.channel IS NOT NULL THEN
                        CASE WHEN own.allowed THEN 'consent_record_found'
                             WHEN left(own.reason, 8) = 'stopped:' THEN 'stop_on_record'
                             ELSE 'no_record' END
                    WHEN star.channel IS NOT NULL AND left(star.reason, 8) = 'stopped:' THEN 'stop_on_record'
                    ELSE 'no_record' END AS status
          FROM consentvault.channel ch
          LEFT JOIN consentvault.purpose pu ON pu.org_id = ch.org_id
          LEFT JOIN cp own ON own.channel = ch.channel AND own.purpose = pu.purpose
          LEFT JOIN cp star ON star.channel = ch.channel AND star.purpose = '*'
         WHERE ch.org_id = p_org
    )
    SELECT coalesce(jsonb_object_agg(x.channel, x.by_purpose), '{}'::jsonb),
           coalesce(bool_or(x.any_stop), false)
      INTO cell_json, stopped
      FROM (SELECT channel,
                   coalesce(jsonb_object_agg(purpose, status) FILTER (WHERE purpose IS NOT NULL), '{}'::jsonb) AS by_purpose,
                   coalesce(bool_or(status = 'stop_on_record') FILTER (WHERE purpose IS NOT NULL), false) AS any_stop
              FROM cells GROUP BY channel) x;

    SELECT max(e.received_at) FILTER (WHERE e.event_type IN ('revoke', 'suppress')), max(e.received_at)
      INTO stop_at, last_at
      FROM consentvault.post_history_all_events e
     WHERE e.org_id = p_org AND e.contact_fp = r.contact_fp AND e.seq >= r.first_seq AND (nxt IS NULL OR e.seq < nxt);
    -- the person: the newest event of this record that carried a person key of its own. An event with none (a STOP texted in,
    -- a stop-page click, an unkeyed capture) holds the contact's default key and never moves or breaks the link. A record that
    -- never carried a person key keeps its default key, which no other record shares, so it links to nothing.
    IF p_default_subject_fp IS NOT NULL AND p_default_subject_fp !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'consentvault records: the default subject fingerprint is not a fingerprint' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT coalesce(p_default_subject_fp, i.default_subject_fp) INTO dflt FROM consentvault.record_index i
     WHERE i.org_id = p_org AND i.record_id = p_record_id;
    dflt := coalesce(dflt, p_default_subject_fp);
    -- only the contact's own key opens its contact point, so a contact erased before its record was made (the backfill) has no
    -- default to give; an erased record links to nothing whatever its subject. Any other record without one is refused.
    IF dflt IS NULL AND (r.erased_at IS NULL AND EXISTS (SELECT 1 FROM consentvault.contact_key k
                                                          WHERE k.org_id = p_org AND k.contact_fp = r.contact_fp)) THEN
        RAISE EXCEPTION 'consentvault records: record % has no default subject fingerprint; the writer supplies it', p_record_id
            USING ERRCODE = 'null_value_not_allowed';
    END IF;
    SELECT e.subject_fp INTO subj FROM consentvault.post_history_all_events e
     WHERE e.org_id = p_org AND e.contact_fp = r.contact_fp AND e.seq >= r.first_seq AND (nxt IS NULL OR e.seq < nxt)
       AND e.subject_fp IS DISTINCT FROM dflt
     ORDER BY e.seq DESC LIMIT 1;
    subj := coalesce(subj, dflt);
    SELECT s.source_id INTO first_src FROM consentvault.post_history_all_events s
     WHERE s.org_id = p_org AND s.contact_fp = r.contact_fp AND s.seq >= r.first_seq AND (nxt IS NULL OR s.seq < nxt)
       AND s.source_id IS NOT NULL ORDER BY s.seq LIMIT 1;
    SELECT coalesce(array_agg(g.source_id ORDER BY g.first_seq), '{}') INTO srcs
      FROM (SELECT s.source_id, min(s.seq) AS first_seq FROM consentvault.post_history_all_events s
             WHERE s.org_id = p_org AND s.contact_fp = r.contact_fp AND s.seq >= r.first_seq AND (nxt IS NULL OR s.seq < nxt)
               AND s.source_id IS NOT NULL GROUP BY s.source_id) g;
    SELECT coalesce(array_agg(DISTINCT b ORDER BY b), '{}') INTO brs
      FROM consentvault.post_history_all_events e, unnest(e.brand_ids) AS b
     WHERE e.org_id = p_org AND e.contact_fp = r.contact_fp AND e.seq >= r.first_seq AND (nxt IS NULL OR e.seq < nxt);
    SELECT o.status = 'trial' INTO trial FROM consentvault.organization o WHERE o.org_id = p_org;

    INSERT INTO consentvault.record_index (org_id, record_id, subject_fp, default_subject_fp, last_event_at, first_source_id, source_ids, brand_ids,
                                           status_by_cell, has_stop, last_stop_at, first_in_trial, mask_ct)
    VALUES (p_org, p_record_id, subj, dflt, coalesce(last_at, r.first_recorded_at), first_src, srcs, brs, cell_json, stopped, stop_at,
            coalesce(trial, false), CASE WHEN r.erased_at IS NULL THEN p_mask_ct END)
    ON CONFLICT (org_id, record_id) DO UPDATE
       SET subject_fp = EXCLUDED.subject_fp, default_subject_fp = EXCLUDED.default_subject_fp, last_event_at = EXCLUDED.last_event_at,
           first_source_id = EXCLUDED.first_source_id, source_ids = EXCLUDED.source_ids, brand_ids = EXCLUDED.brand_ids,
           status_by_cell = EXCLUDED.status_by_cell, has_stop = EXCLUDED.has_stop, last_stop_at = EXCLUDED.last_stop_at,
           mask_ct = CASE WHEN r.erased_at IS NULL THEN coalesce(consentvault.record_index.mask_ct, EXCLUDED.mask_ct)
                          ELSE NULL END;
END;
$$;
CREATE OR REPLACE FUNCTION consentvault.record_index_refresh(p_event_id uuid, p_contact_fp text, p_mask_ct bytea,
                                                  p_default_subject_fp text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
    ev  record;
    rid uuid;
BEGIN
    SELECT e.contact_fp AS fp INTO ev FROM consentvault.post_history_all_events e WHERE e.org_id = org AND e.event_id = p_event_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: event % is not in the current organisation', p_event_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF ev.fp IS DISTINCT FROM p_contact_fp THEN
        RAISE EXCEPTION 'consentvault records: event % is not for that contact fingerprint', p_event_id
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(consentvault.ledger_lock_key(org));
    SELECT r.record_id INTO rid FROM consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND r.erased_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: no active record for that fingerprint; record_upsert comes first'
            USING ERRCODE = 'no_data_found';
    END IF;
    PERFORM consentvault.record_index_derive(org, rid, p_mask_ct, p_default_subject_fp);
END;
$$;
CREATE OR REPLACE FUNCTION consentvault.record_index_without_default() RETURNS TABLE (contact_fp text, event_id uuid)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin']);
BEGIN
    RETURN QUERY
    SELECT r.contact_fp,
           (SELECT e.event_id FROM consentvault.post_history_all_events e WHERE e.org_id = r.org_id AND e.contact_fp = r.contact_fp
             ORDER BY e.seq DESC LIMIT 1)
      FROM consentvault.record r JOIN consentvault.record_index i ON i.org_id = r.org_id AND i.record_id = r.record_id
     WHERE r.org_id = org AND r.erased_at IS NULL AND i.default_subject_fp IS NULL
     ORDER BY r.first_seq;
END;
$$;
CREATE OR REPLACE FUNCTION consentvault.usage_events_for_day(p_day date) RETURNS bigint
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    RETURN (SELECT count(*) FROM consentvault.post_history_all_events e
             WHERE e.org_id = org
               AND e.received_at >= (p_day::timestamp AT TIME ZONE 'UTC')
               AND e.received_at < ((p_day + 1)::timestamp AT TIME ZONE 'UTC'));
END;
$$;
CREATE OR REPLACE FUNCTION consentvault.erasure_request_cover() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM consentvault.contact_key k
                WHERE k.org_id OPERATOR(pg_catalog.=) NEW.org_id AND k.contact_fp OPERATOR(pg_catalog.=) NEW.contact_fp) THEN
        RAISE EXCEPTION 'consentvault.erasure_request: a request is completed only after its contact key is deleted; the contact key still exists'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- the head is read under the organisation's ledger lock: a writer still holding it commits first and is covered
    PERFORM pg_catalog.pg_advisory_xact_lock(consentvault.ledger_lock_key(NEW.org_id));
    INSERT INTO consentvault.erasure_coverage (org_id, erasure_id, covers_through_seq)
    SELECT NEW.org_id, NEW.erasure_id, coalesce(pg_catalog.max(e.seq), 0) FROM consentvault.post_history_all_events e
     WHERE e.org_id OPERATOR(pg_catalog.=) NEW.org_id;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION consentvault.customer_alarm_rows(p_admin boolean)
    RETURNS TABLE (name text, since timestamptz, count integer)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'audit_read', 'proof_read']);
BEGIN
    IF p_admin AND NOT coalesce(consentvault.current_token_scopes() && ARRAY['admin'], false) THEN
        RAISE EXCEPTION 'consentvault: the admin alarms need the admin scope' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN QUERY
    SELECT 'restore.stops_unconfirmed'::text, min(e.received_at), count(*)::integer
      FROM consentvault.post_history_all_events e
     WHERE e.org_id = org AND e.source = 'erasure' AND e.recorded_by LIKE 'erasure-unconfirmed:%'
       AND NOT EXISTS (SELECT 1 FROM consentvault.post_history_all_events g WHERE g.org_id = org AND g.contact_fp = e.contact_fp
                          AND g.seq > e.seq AND g.event_type IN ('grant', 'release'))
       AND NOT EXISTS (SELECT 1 FROM consentvault.post_history_all_events c WHERE c.org_id = org AND c.source = 'erasure'
                          AND c.recorded_by = 'erasure:' || substr(e.recorded_by, length('erasure-unconfirmed:') + 1))
    HAVING count(*) > 0;
    IF p_admin THEN
        RETURN QUERY
        SELECT a.name::text, min(a.raised_at), NULL::integer FROM consentvault.operator_alarm a
         WHERE a.org_id = org AND a.name = 'billing.second_live_subscription' AND a.acknowledged_at IS NULL
         GROUP BY a.name;
    END IF;
END;
$$;
-- health counts and the last event of each source count history rows, sealed by the history seal table.
CREATE OR REPLACE FUNCTION consentvault.health_counts()
    RETURNS TABLE (unsealed_over_1h bigint, first_event_at timestamptz, first_event_sealed boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT (SELECT count(*) FROM consentvault.post_history_all_events e
             WHERE e.org_id = (SELECT consentvault.current_org()) AND e.received_at < clock_timestamp() - interval '1 hour'
               AND NOT EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.org_id = e.org_id AND s.event_id = e.event_id)
               AND NOT EXISTS (SELECT 1 FROM consentvault.post_history_seal h JOIN consentvault.post_history p
                                ON p.org_id = h.org_id AND p.history_seq = h.history_seq WHERE p.org_id = e.org_id AND p.event_id = e.event_id)),
           f.received_at,
           CASE WHEN f.event_id IS NULL THEN NULL
                ELSE EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.org_id = f.org_id AND s.event_id = f.event_id)
                  OR EXISTS (SELECT 1 FROM consentvault.post_history_seal h JOIN consentvault.post_history p
                              ON p.org_id = h.org_id AND p.history_seq = h.history_seq WHERE p.org_id = f.org_id AND p.event_id = f.event_id) END
    FROM (SELECT 1) one
    LEFT JOIN LATERAL (SELECT e.org_id, e.event_id, e.received_at FROM consentvault.post_history_all_events e
                        WHERE e.org_id = (SELECT consentvault.current_org()) ORDER BY e.seq LIMIT 1) f ON true;
$$;

CREATE OR REPLACE FUNCTION consentvault.source_last_events()
    RETURNS TABLE (source_id uuid, last_event_at timestamptz, last_event_seq bigint, last_event_sealed boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT DISTINCT ON (e.source_id) e.source_id, e.received_at, e.seq,
           EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.org_id = e.org_id AND s.event_id = e.event_id)
             OR EXISTS (SELECT 1 FROM consentvault.post_history_seal h JOIN consentvault.post_history p
                         ON p.org_id = h.org_id AND p.history_seq = h.history_seq WHERE p.org_id = e.org_id AND p.event_id = e.event_id)
    FROM consentvault.post_history_all_events e
    WHERE e.org_id = (SELECT consentvault.current_org()) AND e.source_id IS NOT NULL
    ORDER BY e.source_id, e.seq DESC;
$$;

-- The receipt of one event or history row (no personal field). Out of band, with no organisation entered, a database superuser reads it by id.
CREATE OR REPLACE FUNCTION consentvault.receipt_of(p_event_id uuid)
    RETURNS TABLE (seq bigint, row_hash text, received_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT e.chain_seq, e.row_hash, e.received_at FROM consentvault.post_history_all_events e
     WHERE e.event_id = p_event_id
       AND (e.org_id = consentvault.current_org()
            OR (consentvault.current_org() IS NULL AND (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user)))
     ORDER BY (e.seq = e.chain_seq) DESC LIMIT 1;
$$;
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
ALTER FUNCTION consentvault.receipt_of(uuid) OWNER TO consentvault_operator;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
GRANT SELECT ON consentvault.event, consentvault.post_history, consentvault.post_history_all_events, consentvault.history_events TO consentvault_operator;
GRANT SELECT ON consentvault.raw_post, consentvault.raw_post_original_arrival, consentvault.event_source_post TO consentvault_operator;

-- The documentation check of a record is the completeness its history row recorded at projection (gate 8). The earlier function, which took
-- a checklist version and the lists a person supplied, keeps its body under a new name for the admin route that stores a checked list.
ALTER FUNCTION consentvault.record_doc_check(uuid, integer, text[], text[], uuid) RENAME TO record_doc_check_stored;
CREATE FUNCTION consentvault.record_doc_check(p_event_id uuid) RETURNS jsonb
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT h.completeness FROM consentvault.post_history h
     WHERE h.org_id OPERATOR(pg_catalog.=) consentvault.current_org() AND h.event_id OPERATOR(pg_catalog.=) p_event_id;
$$;
REVOKE ALL ON FUNCTION consentvault.record_doc_check(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.record_doc_check(uuid) TO consentvault_app;

-- The history stop reader answers yes or no. Its rule set is named by its own function. Owned by the operator role (row security bypassed)
-- so a database superuser can ask out of band for an organisation by id; a session that has entered an organisation can ask only about
-- that one, and an ordinary session with none entered is refused by name.
DROP FUNCTION consentvault.history_stop_on_record(uuid, text, text);
CREATE FUNCTION consentvault.history_stop_on_record(p_org uuid, p_contact_fp text, p_channel text) RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF consentvault.current_org() IS NULL THEN
        IF NOT (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user) THEN
            RAISE EXCEPTION 'consentvault stop check: no organisation is entered, so no answer can be given' USING ERRCODE = 'insufficient_privilege';
        END IF;
    ELSIF p_org IS DISTINCT FROM consentvault.current_org() THEN
        RAISE EXCEPTION 'consentvault stop check: the question names an organisation other than the one entered' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM consentvault.post_history h
         WHERE h.org_id OPERATOR(pg_catalog.=) p_org AND h.contact_fp OPERATOR(pg_catalog.=) p_contact_fp
           AND h.event_type_sent OPERATOR(pg_catalog.=) ANY (ARRAY['revoke', 'suppress']::pg_catalog.text[])
           AND h.standing OPERATOR(pg_catalog.=) 'counts' AND h.earliest_copy
           AND p_channel OPERATOR(pg_catalog.=) ANY (h.channels_sent)
           AND (NOT EXISTS (SELECT 1 FROM consentvault.history_stop_lift l
                             WHERE l.org_id OPERATOR(pg_catalog.=) h.org_id AND l.stop_event_id OPERATOR(pg_catalog.=) h.event_id)
                OR h.origin_sent IS DISTINCT FROM 'consumer' OR h.method_sent IS NULL
                OR h.method_sent NOT IN ('keyword', 'checkbox', 'written')));
END;
$$;
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
ALTER FUNCTION consentvault.history_stop_on_record(uuid, text, text) OWNER TO consentvault_operator;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.history_stop_on_record(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.history_stop_on_record(uuid, text, text) TO consentvault_app, consentvault_worker;
GRANT SELECT ON consentvault.history_stop_lift, consentvault.post_history_seal TO consentvault_operator;
-- The erasure job runs as the operator console: its stop is a post, and the post's history row is written by the same fold.
GRANT INSERT (org_id, post_id, post_seq, placed_at, received_at, event_id, label, event_type_sent, channels_sent, purposes_sent,
              method_sent, origin_sent, contact_kind_sent, captured_at_sent, wording_sha256_sent, contact_verification_sent,
              source_id_sent, brand_ids_sent, wording_fact_id, standing, earliest_copy, contact_fp, contact_key_ref, completeness,
              facts_read, rule_set_version, intake_code_version, fold_code_version, contact_ct, contact_nonce, display_ct,
              display_nonce, backfill_of_event_id, hash_version)
    ON consentvault.post_history TO consentvault_console;
CREATE FUNCTION consentvault.history_stop_rule_set_version() RETURNS text LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$ SELECT 'stopped-rule-0075'::text $$;
GRANT EXECUTE ON FUNCTION consentvault.history_stop_rule_set_version() TO consentvault_app, consentvault_worker;
