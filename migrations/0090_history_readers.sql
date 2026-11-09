-- Pure projection, migration step 9 (specs/capture-everything/pure-projection.md, "Migration 0088": renumbered 0090). History-reading SQL
-- BESIDE the old: nothing the old fold calls (ledger_head, chain_breaks, unsealed_events, confirmation_enqueue, the sync and record
-- functions, current_permission) is replaced or touched here; those retire only inside the cutover window.
--
-- history_head(): the newest history row of the entered organisation (out of band, with no organisation entered, the newest visible).
-- An invoker: row security and the evidence read scope bind the caller, as they bind a direct read of the history.
CREATE FUNCTION consentvault.history_head() RETURNS TABLE (seq bigint, row_hash text)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT h.history_seq, h.row_hash FROM consentvault.post_history h
     WHERE h.org_id OPERATOR(pg_catalog.=) coalesce(consentvault.current_org(), h.org_id)
     ORDER BY CASE WHEN consentvault.current_org() IS NULL THEN h.recorded_at END DESC NULLS LAST, h.history_seq DESC LIMIT 1;
$$;
REVOKE ALL ON FUNCTION consentvault.history_head() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.history_head() TO consentvault_app, consentvault_worker, consentvault_integrity, consentvault_console;

-- history_chain_breaks(): every link that does not extend the row before it, and every row hash that does not recompute from the
-- stored columns. The hash covers ciphertexts, never a key, so rows of an erased contact verify with no contact key present.
CREATE FUNCTION consentvault.history_chain_breaks() RETURNS TABLE (org_id uuid, history_seq bigint, reason text)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH ordered AS (
        SELECT h.*, pg_catalog.lag(h.row_hash) OVER (PARTITION BY h.org_id ORDER BY h.history_seq) AS before_hash,
               pg_catalog.lag(h.history_seq) OVER (PARTITION BY h.org_id ORDER BY h.history_seq) AS before_seq
          FROM consentvault.post_history h)
    SELECT o.org_id, o.history_seq, 'prev_hash is not the previous row''s hash'
      FROM ordered o WHERE o.prev_hash IS DISTINCT FROM coalesce(o.before_hash, pg_catalog.repeat('0', 64))
    UNION ALL
    SELECT o.org_id, o.history_seq, 'history_seq is not the previous row''s plus one'
      FROM ordered o WHERE o.history_seq IS DISTINCT FROM coalesce(o.before_seq, 0) OPERATOR(pg_catalog.+) 1
    UNION ALL
    SELECT o.org_id, o.history_seq, 'row_hash does not recompute from the stored columns'
      FROM ordered o
     WHERE o.row_hash IS DISTINCT FROM pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
               o.prev_hash OPERATOR(pg_catalog.||) ((pg_catalog.to_jsonb(o) OPERATOR(pg_catalog.-) 'row_hash'::pg_catalog.text
                                                      OPERATOR(pg_catalog.-) 'prev_hash'::pg_catalog.text
                                                      OPERATOR(pg_catalog.-) 'recorded_at'::pg_catalog.text
                                                      OPERATOR(pg_catalog.-) 'before_hash'::pg_catalog.text
                                                      OPERATOR(pg_catalog.-) 'before_seq'::pg_catalog.text)::pg_catalog.text), 'UTF8')), 'hex');
$$;
REVOKE ALL ON FUNCTION consentvault.history_chain_breaks() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.history_chain_breaks() TO consentvault_app, consentvault_worker, consentvault_integrity, consentvault_console;

-- unsealed_history(): the history rows with no seal yet (event_id, as unsealed_events lists), oldest first.
CREATE FUNCTION consentvault.unsealed_history() RETURNS TABLE (org_id uuid, history_seq bigint, event_id uuid)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT h.org_id, h.history_seq, h.event_id FROM consentvault.post_history h
     WHERE NOT EXISTS (SELECT 1 FROM consentvault.post_history_seal s
                        WHERE s.org_id OPERATOR(pg_catalog.=) h.org_id AND s.history_seq OPERATOR(pg_catalog.=) h.history_seq)
     ORDER BY h.org_id, h.history_seq;
$$;
REVOKE ALL ON FUNCTION consentvault.unsealed_history() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.unsealed_history() TO consentvault_app, consentvault_worker, consentvault_integrity, consentvault_console;

-- history_stop_on_record(): today's stopped rule (migration 0075), computed over history and used by the sender only. A counted,
-- first-copy stop on the channel (any purpose: the star rule) is on record unless it was lifted (history_stop_lift) and it is not a
-- hard stop (an origin other than the consumer, or a method other than a keyword, checkbox or written one). Named with its rule set.
CREATE FUNCTION consentvault.history_stop_on_record(p_org uuid, p_contact_fp text, p_channel text)
    RETURNS TABLE (stopped boolean, stop_event_id uuid, rule_set_version text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT true, h.event_id, 'stopped-rule-0075'::pg_catalog.text
      FROM consentvault.post_history h
     WHERE h.org_id OPERATOR(pg_catalog.=) p_org AND h.contact_fp OPERATOR(pg_catalog.=) p_contact_fp
       AND h.event_type_sent OPERATOR(pg_catalog.=) ANY (ARRAY['revoke', 'suppress']::pg_catalog.text[])
       AND h.standing OPERATOR(pg_catalog.=) 'counts' AND h.earliest_copy
       AND p_channel OPERATOR(pg_catalog.=) ANY (h.channels_sent)
       AND (NOT EXISTS (SELECT 1 FROM consentvault.history_stop_lift l
                         WHERE l.org_id OPERATOR(pg_catalog.=) h.org_id AND l.stop_event_id OPERATOR(pg_catalog.=) h.event_id)
            OR h.origin_sent IS DISTINCT FROM 'consumer' OR h.method_sent IS NULL
            OR h.method_sent NOT IN ('keyword', 'checkbox', 'written'))
     ORDER BY h.placed_at DESC, h.post_seq DESC LIMIT 1;
$$;
REVOKE ALL ON FUNCTION consentvault.history_stop_on_record(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.history_stop_on_record(uuid, text, text) TO consentvault_app, consentvault_worker;

-- The pure fold's three reads, as definers of the entered organisation, so the fold runs in any context that wrote the post: the
-- intake's capture token writes a post but cannot read it back (the evidence read scope), and the post's history row is still
-- projected in the same call. Each returns what the stored rows say, nothing else, and takes the organisation from the token.
CREATE FUNCTION consentvault.fold_post_place(p_post uuid) RETURNS TABLE (post_seq bigint, received_at timestamptz, placed_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT rp.seq, rp.received_at, LEAST(rp.received_at, coalesce(oa.arrived_at, rp.received_at))
      FROM consentvault.raw_post rp
      LEFT JOIN consentvault.raw_post_original_arrival oa ON oa.org_id OPERATOR(pg_catalog.=) rp.org_id AND oa.post_id OPERATOR(pg_catalog.=) rp.post_id
     WHERE rp.org_id OPERATOR(pg_catalog.=) consentvault.current_org() AND rp.post_id OPERATOR(pg_catalog.=) p_post;
$$;
CREATE FUNCTION consentvault.fold_fact_rows(p_post uuid) RETURNS TABLE (source text, name text, value_ct bytea)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT DISTINCT ON (f.source, f.name) f.source, f.name, f.value_ct
      FROM consentvault.raw_post_fact f
     WHERE f.org_id OPERATOR(pg_catalog.=) consentvault.current_org() AND f.post_id OPERATOR(pg_catalog.=) p_post
       AND f.status IN ('value', 'not_found', 'not_applicable', 'unparseable')
     ORDER BY f.source, f.name, f.fact_seq;
$$;
CREATE FUNCTION consentvault.fold_earliest_copy(p_post uuid, p_request_key text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT p_request_key IS NULL OR NOT EXISTS (
        SELECT 1 FROM consentvault.raw_post_request q JOIN consentvault.raw_post p
          ON p.org_id OPERATOR(pg_catalog.=) q.org_id AND p.post_id OPERATOR(pg_catalog.=) q.post_id
         WHERE q.org_id OPERATOR(pg_catalog.=) consentvault.current_org() AND q.request_key OPERATOR(pg_catalog.=) p_request_key
           AND p.seq OPERATOR(pg_catalog.<) (SELECT mine.seq FROM consentvault.raw_post mine
                                            WHERE mine.org_id OPERATOR(pg_catalog.=) q.org_id AND mine.post_id OPERATOR(pg_catalog.=) p_post));
$$;
REVOKE ALL ON FUNCTION consentvault.fold_post_place(uuid), consentvault.fold_fact_rows(uuid), consentvault.fold_earliest_copy(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.fold_post_place(uuid), consentvault.fold_fact_rows(uuid), consentvault.fold_earliest_copy(uuid, text)
    TO consentvault_app, consentvault_worker, consentvault_console;
