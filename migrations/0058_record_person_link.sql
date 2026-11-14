-- Who is linked to whom is decided once, in the records layer (records.md section 1), and every reader takes it from there.
-- Before this, record_index.subject_fp was the subject of a record's newest event of any kind. An event that carried no person
-- key of its own (a STOP texted in, a stop-page click, an unkeyed capture) holds the contact's default key, so one such event
-- broke a link a keyed capture had made, and the email stop page's "stop everything" scanned events for the owner instead.
-- Now the writer supplies the contact's default subject fingerprint (only it holds the fingerprint secret), the index keeps it,
-- and subject_fp is the subject of the newest event that is not the default: an unkeyed event never moves or breaks the link.
-- confirmation_person_contacts is the confirmation service's one door to that link: every other active contact point whose
-- current record belongs to the same person, in one query with no row limit.

ALTER TABLE consentvault.record_index
    ADD COLUMN default_subject_fp text CHECK (default_subject_fp IS NULL OR default_subject_fp ~ '^[0-9a-f]{64}$');

DROP FUNCTION consentvault.record_index_refresh(uuid, text, bytea);
DROP FUNCTION consentvault.record_index_derive(uuid, uuid, bytea);

-- Internal: recompute the derived columns of one record from the ledger. Called only by the definer functions below. -------
CREATE FUNCTION consentvault.record_index_derive(p_org uuid, p_record_id uuid, p_mask_ct bytea, p_default_subject_fp text)
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
      FROM consentvault.event e
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
    SELECT e.subject_fp INTO subj FROM consentvault.event e
     WHERE e.org_id = p_org AND e.contact_fp = r.contact_fp AND e.seq >= r.first_seq AND (nxt IS NULL OR e.seq < nxt)
       AND e.subject_fp IS DISTINCT FROM dflt
     ORDER BY e.seq DESC LIMIT 1;
    subj := coalesce(subj, dflt);
    SELECT s.source_id INTO first_src FROM consentvault.event s
     WHERE s.org_id = p_org AND s.contact_fp = r.contact_fp AND s.seq >= r.first_seq AND (nxt IS NULL OR s.seq < nxt)
       AND s.source_id IS NOT NULL ORDER BY s.seq LIMIT 1;
    SELECT coalesce(array_agg(g.source_id ORDER BY g.first_seq), '{}') INTO srcs
      FROM (SELECT s.source_id, min(s.seq) AS first_seq FROM consentvault.event s
             WHERE s.org_id = p_org AND s.contact_fp = r.contact_fp AND s.seq >= r.first_seq AND (nxt IS NULL OR s.seq < nxt)
               AND s.source_id IS NOT NULL GROUP BY s.source_id) g;
    SELECT coalesce(array_agg(DISTINCT b ORDER BY b), '{}') INTO brs
      FROM consentvault.event e, unnest(e.brand_ids) AS b
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
REVOKE ALL ON FUNCTION consentvault.record_index_derive(uuid, uuid, bytea, text) FROM PUBLIC;

CREATE FUNCTION consentvault.record_index_refresh(p_event_id uuid, p_contact_fp text, p_mask_ct bytea,
                                                  p_default_subject_fp text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
    ev  record;
    rid uuid;
BEGIN
    SELECT e.contact_fp AS fp INTO ev FROM consentvault.event e WHERE e.org_id = org AND e.event_id = p_event_id;
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
REVOKE ALL ON FUNCTION consentvault.record_index_refresh(uuid, text, bytea, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.record_index_refresh(uuid, text, bytea, text) TO consentvault_app, consentvault_console;

CREATE OR REPLACE FUNCTION consentvault.record_index_rebuild(p_record_id uuid) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin']);
BEGIN
    PERFORM pg_advisory_xact_lock(consentvault.ledger_lock_key(org));
    PERFORM 1 FROM consentvault.record r WHERE r.org_id = org AND r.record_id = p_record_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: record % is not in the current organisation', p_record_id
            USING ERRCODE = 'no_data_found';
    END IF;
    PERFORM consentvault.record_index_derive(org, p_record_id, NULL, NULL);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_index_rebuild(uuid) FROM PUBLIC;

-- The confirmation service's door to the person link: every other active contact point whose current record belongs to the
-- same person as this contact's current record: the same subject_fp the records list counts as linked. None when this contact
-- has no active record. A contact that never carried a person key still matches a record keyed with its own hash (an
-- integration that keys the person by the email's hash), exactly as the list shows them linked.
CREATE FUNCTION consentvault.confirmation_person_contacts(p_contact_fp text)
    RETURNS TABLE (contact_fp text, contact_kind text, event_id uuid)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org  uuid := consentvault.sync_org(ARRAY['worker:confirmations']);
    me   record;
BEGIN
    SELECT i.subject_fp AS subj, i.default_subject_fp AS dflt INTO me
      FROM consentvault.record r JOIN consentvault.record_index i ON i.org_id = r.org_id AND i.record_id = r.record_id
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND r.erased_at IS NULL;
    IF NOT FOUND OR me.subj IS NULL THEN
        RETURN;
    END IF;
    RETURN QUERY
    SELECT r.contact_fp, r.contact_kind,
           (SELECT e.event_id FROM consentvault.event e WHERE e.org_id = r.org_id AND e.contact_fp = r.contact_fp
             ORDER BY e.seq DESC LIMIT 1)
      FROM consentvault.record r JOIN consentvault.record_index i ON i.org_id = r.org_id AND i.record_id = r.record_id
     WHERE r.org_id = org AND r.erased_at IS NULL AND i.subject_fp = me.subj AND r.contact_fp <> p_contact_fp
     ORDER BY r.first_recorded_at, r.record_id;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_person_contacts(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_person_contacts(text) TO consentvault_app;

-- The backfill's door to the indexes written before this migration (no default subject fingerprint yet), with the newest event
-- of each so the writer can open the contact point and supply the default.
CREATE FUNCTION consentvault.record_index_without_default() RETURNS TABLE (contact_fp text, event_id uuid)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin']);
BEGIN
    RETURN QUERY
    SELECT r.contact_fp,
           (SELECT e.event_id FROM consentvault.event e WHERE e.org_id = r.org_id AND e.contact_fp = r.contact_fp
             ORDER BY e.seq DESC LIMIT 1)
      FROM consentvault.record r JOIN consentvault.record_index i ON i.org_id = r.org_id AND i.record_id = r.record_id
     WHERE r.org_id = org AND r.erased_at IS NULL AND i.default_subject_fp IS NULL
     ORDER BY r.first_seq;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_index_without_default() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.record_index_without_default() TO consentvault_console;
