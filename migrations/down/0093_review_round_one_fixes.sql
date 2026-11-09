-- Reverses 0093_review_round_one_fixes.sql: the functions are the ones migrations 0084, 0086, 0089 and 0090 made, the reroute row is
-- insertable by the runtime role again, and the loader nonce table is dropped. On the pinned guards this runs as the superuser followed
-- by consentvault_guard.repin(). No post, fact or history row is touched.
BEGIN;
GRANT INSERT (from_org, from_post, to_org, to_post) ON consentvault.raw_post_reroute TO consentvault_app;
DROP FUNCTION consentvault.record_reroute(uuid, uuid, uuid);
REVOKE INSERT (from_org, from_post, to_org, to_post) ON consentvault.raw_post_reroute FROM consentvault_operator;
DROP FUNCTION consentvault.history_stop_on_record(uuid, text, text);
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
CREATE OR REPLACE FUNCTION consentvault.check_stop_lift() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    stop_at pg_catalog.timestamptz;
    post_at pg_catalog.timestamptz;
BEGIN
    IF TG_TABLE_NAME OPERATOR(pg_catalog.=) 'history_stop_lift' THEN
        SELECT h.placed_at INTO stop_at
        FROM consentvault.post_history h
        WHERE h.org_id OPERATOR(pg_catalog.=) NEW.org_id
          AND h.event_id OPERATOR(pg_catalog.=) NEW.stop_event_id
          AND h.event_type_sent OPERATOR(pg_catalog.=) ANY (ARRAY['revoke', 'suppress']::pg_catalog.text[])
          AND h.contact_fp OPERATOR(pg_catalog.=) NEW.contact_fp;
    ELSE
        SELECT e.received_at INTO stop_at
        FROM consentvault.event e
        WHERE e.org_id OPERATOR(pg_catalog.=) NEW.org_id
          AND e.event_id OPERATOR(pg_catalog.=) NEW.stop_event_id
          AND e.event_type OPERATOR(pg_catalog.=) ANY (ARRAY['revoke', 'suppress']::pg_catalog.text[])
          AND e.contact_fp OPERATOR(pg_catalog.=) NEW.contact_fp;
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault stop lift: the stop named is not a stop of this contact point'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM consentvault.raw_post_match m
                   WHERE m.org_id OPERATOR(pg_catalog.=) NEW.org_id
                     AND m.post_id OPERATOR(pg_catalog.=) NEW.lifting_post_id
                     AND m.status OPERATOR(pg_catalog.=) 'matched'
                     AND m.contact_fp OPERATOR(pg_catalog.=) NEW.contact_fp) THEN
        RAISE EXCEPTION 'consentvault stop lift: the lifting post is not matched to the same contact point'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    SELECT p.received_at INTO post_at
    FROM consentvault.raw_post p
    WHERE p.org_id OPERATOR(pg_catalog.=) NEW.org_id AND p.post_id OPERATOR(pg_catalog.=) NEW.lifting_post_id;
    IF post_at OPERATOR(pg_catalog.<=) stop_at THEN
        RAISE EXCEPTION 'consentvault stop lift: the lifting post did not arrive after the stop'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION consentvault.post_history_chain() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_head   record;
    v_post   record;
    v_placed timestamptz;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('post_history' OPERATOR(pg_catalog.||) NEW.org_id::pg_catalog.text, 0));
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
CREATE OR REPLACE FUNCTION consentvault.load_stored_post(p_doc jsonb) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_post uuid;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM consentvault.replay_target) THEN
        RAISE EXCEPTION 'consentvault load refused: this database carries no replay mark (it is a store of record)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_doc ? 'post' THEN
        v_post := (p_doc -> 'post' ->> 'post_id')::pg_catalog.uuid;
        PERFORM pg_catalog.set_config('consentvault.loading_post', v_post::pg_catalog.text, true);
        INSERT INTO consentvault.raw_post SELECT * FROM pg_catalog.jsonb_populate_record(NULL::consentvault.raw_post, p_doc -> 'post');
        IF p_doc ? 'key' AND p_doc -> 'key' <> 'null'::pg_catalog.jsonb THEN
            INSERT INTO consentvault.raw_post_key SELECT * FROM pg_catalog.jsonb_populate_record(NULL::consentvault.raw_post_key, p_doc -> 'key');
        END IF;
        INSERT INTO consentvault.raw_post_fact SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.raw_post_fact, p_doc -> 'facts')
            AS f ORDER BY f.fact_seq NULLS FIRST;
        INSERT INTO consentvault.raw_post_request SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.raw_post_request, p_doc -> 'requests');
        INSERT INTO consentvault.raw_post_original_arrival SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.raw_post_original_arrival, p_doc -> 'original_arrival');
        INSERT INTO consentvault.raw_post_seal SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.raw_post_seal, p_doc -> 'seals');
    END IF;
    -- after every post of every organisation is in (a reroute cites a post of two organisations), the reroute rows and the anchors
    INSERT INTO consentvault.raw_post_reroute SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.raw_post_reroute, p_doc -> 'reroutes');
    INSERT INTO consentvault.raw_post_chain_head SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.raw_post_chain_head, p_doc -> 'anchors');
END;
$$;
CREATE OR REPLACE FUNCTION consentvault.loading_allowed(p_post uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM consentvault.replay_target)
       AND p_post IS NOT NULL
       AND coalesce(pg_catalog.current_setting('consentvault.loading_post', true), '') OPERATOR(pg_catalog.=) p_post::pg_catalog.text;
$$;
DROP TABLE consentvault.replay_load_nonce;
COMMIT;
