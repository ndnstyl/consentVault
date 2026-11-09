-- Pure projection, gate 3: a backfill history row is written by the fold from the post's legacy-event fact, so a replay of the store writes
-- the same row. The replay database holds no event table rows to match, so the match against a legacy event (migration 0093) is required
-- everywhere except on a replay database, which carries the mark and is never a store of record.
CREATE OR REPLACE FUNCTION consentvault.post_history_chain() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_head   record;
    v_post   record;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('post_history' OPERATOR(pg_catalog.||) NEW.org_id::pg_catalog.text, 0));
    IF NEW.label OPERATOR(pg_catalog.=) 'backfill' AND NOT EXISTS (SELECT 1 FROM consentvault.replay_target) THEN
        IF NEW.backfill_of_event_id IS NULL OR NEW.event_id IS DISTINCT FROM NEW.backfill_of_event_id
           OR NOT EXISTS (SELECT 1 FROM consentvault.event e
                           WHERE e.org_id OPERATOR(pg_catalog.=) NEW.org_id AND e.event_id OPERATOR(pg_catalog.=) NEW.backfill_of_event_id
                             AND e.received_at OPERATOR(pg_catalog.=) NEW.received_at AND e.event_type OPERATOR(pg_catalog.=) NEW.event_type_sent)
           OR NOT EXISTS (SELECT 1 FROM consentvault.raw_post rp
                           WHERE rp.org_id OPERATOR(pg_catalog.=) NEW.org_id AND rp.post_id OPERATOR(pg_catalog.=) NEW.post_id
                             AND rp.seq OPERATOR(pg_catalog.=) NEW.post_seq) THEN
            RAISE EXCEPTION 'consentvault.post_history: a backfill row must copy a legacy event of this organisation'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    IF NEW.label OPERATOR(pg_catalog.=) 'projected' THEN
        SELECT rp.seq, rp.received_at, LEAST(rp.received_at, coalesce(oa.arrived_at, rp.received_at)) AS placed
          INTO v_post
          FROM consentvault.raw_post rp
          LEFT JOIN consentvault.raw_post_original_arrival oa ON oa.org_id OPERATOR(pg_catalog.=) rp.org_id AND oa.post_id OPERATOR(pg_catalog.=) rp.post_id
         WHERE rp.org_id OPERATOR(pg_catalog.=) NEW.org_id AND rp.post_id OPERATOR(pg_catalog.=) NEW.post_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'consentvault.post_history: the cited post is not stored' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        IF NEW.post_seq IS DISTINCT FROM v_post.seq OR NEW.received_at IS DISTINCT FROM v_post.received_at
           OR NEW.placed_at IS DISTINCT FROM v_post.placed THEN
            RAISE EXCEPTION 'consentvault.post_history: a projected row''s arrival and place must equal the stored post'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    SELECT h.history_seq, h.row_hash INTO v_head FROM consentvault.post_history h
     WHERE h.org_id OPERATOR(pg_catalog.=) NEW.org_id ORDER BY h.history_seq DESC LIMIT 1;
    NEW.history_seq := coalesce(v_head.history_seq, 0) OPERATOR(pg_catalog.+) 1;
    NEW.prev_hash := coalesce(v_head.row_hash, pg_catalog.repeat('0', 64));
    NEW.recorded_at := pg_catalog.clock_timestamp();
    NEW.row_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
        NEW.prev_hash OPERATOR(pg_catalog.||) ((pg_catalog.to_jsonb(NEW) OPERATOR(pg_catalog.-) 'row_hash'::pg_catalog.text
                                                OPERATOR(pg_catalog.-) 'prev_hash'::pg_catalog.text
                                                OPERATOR(pg_catalog.-) 'recorded_at'::pg_catalog.text)::pg_catalog.text), 'UTF8')), 'hex');
    RETURN NEW;
END;
$$;
