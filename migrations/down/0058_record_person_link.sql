-- Reverses 0058_record_person_link.sql: a record's subject is again the subject of its newest event of any kind, and the
-- confirmation service loses its door to the person link.
BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'consentvault' AND table_name = 'record_index'
                   AND column_name = 'default_subject_fp') THEN
        RAISE EXCEPTION 'consentvault down 0058 refused: 0058 is not applied';
    END IF;
END
$$;

DROP FUNCTION consentvault.confirmation_person_contacts(text);
DROP FUNCTION consentvault.record_index_without_default();
DROP FUNCTION consentvault.record_index_refresh(uuid, text, bytea, text);
DROP FUNCTION consentvault.record_index_derive(uuid, uuid, bytea, text);
ALTER TABLE consentvault.record_index DROP COLUMN default_subject_fp;

CREATE FUNCTION consentvault.record_index_derive(p_org uuid, p_record_id uuid, p_mask_ct bytea) RETURNS void
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
    SELECT e.subject_fp INTO subj FROM consentvault.event e
     WHERE e.org_id = p_org AND e.contact_fp = r.contact_fp AND e.seq >= r.first_seq AND (nxt IS NULL OR e.seq < nxt)
     ORDER BY e.seq DESC LIMIT 1;
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

    INSERT INTO consentvault.record_index (org_id, record_id, subject_fp, last_event_at, first_source_id, source_ids, brand_ids,
                                           status_by_cell, has_stop, last_stop_at, first_in_trial, mask_ct)
    VALUES (p_org, p_record_id, subj, coalesce(last_at, r.first_recorded_at), first_src, srcs, brs, cell_json, stopped, stop_at,
            coalesce(trial, false), CASE WHEN r.erased_at IS NULL THEN p_mask_ct END)
    ON CONFLICT (org_id, record_id) DO UPDATE
       SET subject_fp = EXCLUDED.subject_fp, last_event_at = EXCLUDED.last_event_at,
           first_source_id = EXCLUDED.first_source_id, source_ids = EXCLUDED.source_ids, brand_ids = EXCLUDED.brand_ids,
           status_by_cell = EXCLUDED.status_by_cell, has_stop = EXCLUDED.has_stop, last_stop_at = EXCLUDED.last_stop_at,
           mask_ct = CASE WHEN r.erased_at IS NULL THEN coalesce(consentvault.record_index.mask_ct, EXCLUDED.mask_ct)
                          ELSE NULL END;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_index_derive(uuid, uuid, bytea) FROM PUBLIC;

CREATE FUNCTION consentvault.record_index_refresh(p_event_id uuid, p_contact_fp text, p_mask_ct bytea) RETURNS void
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
    PERFORM consentvault.record_index_derive(org, rid, p_mask_ct);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_index_refresh(uuid, text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.record_index_refresh(uuid, text, bytea) TO consentvault_app, consentvault_console;

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
    PERFORM consentvault.record_index_derive(org, p_record_id, NULL);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_index_rebuild(uuid) FROM PUBLIC;

COMMIT;
