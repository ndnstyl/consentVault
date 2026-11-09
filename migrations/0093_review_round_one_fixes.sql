-- Pure projection, review round one (2026-11-09) fixes, one migration so the earlier ones stay as committed (0085 was edited after its
-- commit and has never been applied outside a test container). Findings: a backfill-labelled history row can only copy a legacy event;
-- the reroute row is written by a definer that checks the copy; loader mode cannot be switched on by a session setting; a lift compares
-- placement; the history stop reader refuses a session with no organisation entered.

-- Loader mode (finding 5). A session setting is settable by anyone, so it is no proof. The loader function records the post it is loading
-- in a table nobody but the schema owner can touch, inside its own transaction, and removes the row before it returns. No grant is
-- given on the table, so only the definer functions (owned by the schema owner) see it.
CREATE TABLE consentvault.replay_load_nonce (post_id uuid PRIMARY KEY);
REVOKE ALL ON consentvault.replay_load_nonce FROM PUBLIC;
CREATE OR REPLACE FUNCTION consentvault.loading_allowed(p_post uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM consentvault.replay_target)
       AND p_post IS NOT NULL
       AND EXISTS (SELECT 1 FROM consentvault.replay_load_nonce n WHERE n.post_id OPERATOR(pg_catalog.=) p_post);
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
        INSERT INTO consentvault.replay_load_nonce (post_id) VALUES (v_post) ON CONFLICT DO NOTHING;
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
    DELETE FROM consentvault.replay_load_nonce;
    -- after every post of every organisation is in (a reroute cites a post of two organisations), the reroute rows and the anchors
    INSERT INTO consentvault.raw_post_reroute SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.raw_post_reroute, p_doc -> 'reroutes');
    INSERT INTO consentvault.raw_post_chain_head SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.raw_post_chain_head, p_doc -> 'anchors');
END;
$$;


-- The backfill row's origin (finding 2).
CREATE OR REPLACE FUNCTION consentvault.post_history_chain() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_head   record;
    v_post   record;
    v_placed timestamptz;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('post_history' OPERATOR(pg_catalog.||) NEW.org_id::pg_catalog.text, 0));
    IF NEW.label OPERATOR(pg_catalog.=) 'backfill' THEN
        -- a backfill row copies one legacy event and nothing else: the event must exist in this organisation with this id, receipt time
        -- and type, and the cited post must be stored with this sequence number. Dates and values the runtime role makes up are refused.
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


-- A lift compares placement (finding 7).
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
    -- compared by PLACEMENT (the earlier of the post's receipt and its recorded original arrival), as the history orders: a START that
    -- arrived before the stop and was stored again after it does not lift it
    SELECT LEAST(p.received_at, coalesce(oa.arrived_at, p.received_at)) INTO post_at
    FROM consentvault.raw_post p
    LEFT JOIN consentvault.raw_post_original_arrival oa ON oa.org_id OPERATOR(pg_catalog.=) p.org_id AND oa.post_id OPERATOR(pg_catalog.=) p.post_id
    WHERE p.org_id OPERATOR(pg_catalog.=) NEW.org_id AND p.post_id OPERATOR(pg_catalog.=) NEW.lifting_post_id;
    IF post_at OPERATOR(pg_catalog.<=) stop_at THEN
        RAISE EXCEPTION 'consentvault stop lift: the lifting post did not arrive after the stop'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;


-- The history stop reader refuses a session with no organisation, and a question about another organisation (finding 8).
DROP FUNCTION consentvault.history_stop_on_record(uuid, text, text);
CREATE FUNCTION consentvault.history_stop_on_record(p_org uuid, p_contact_fp text, p_channel text)
    RETURNS TABLE (stopped boolean, stop_event_id uuid, rule_set_version text)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF consentvault.current_org() IS NULL THEN
        RAISE EXCEPTION 'consentvault stop check: no organisation is entered, so no answer can be given' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_org IS DISTINCT FROM consentvault.current_org() THEN
        RAISE EXCEPTION 'consentvault stop check: the question names an organisation other than the one entered' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN QUERY
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
END;
$$;
REVOKE ALL ON FUNCTION consentvault.history_stop_on_record(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.history_stop_on_record(uuid, text, text) TO consentvault_app, consentvault_worker;

-- The reroute row (finding 4). The runtime role no longer inserts it: a definer owned by the operator role (row security bypassed, so it can
-- see the copy's organisation) checks that the copy is the same bytes, recorded as arriving when the original did, then writes the row.
-- Every refusal reads the same, so it says nothing about whether a post of another organisation exists.
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
GRANT SELECT (org_id, post_id, received_at, body_sha256) ON consentvault.raw_post TO consentvault_operator;
GRANT SELECT (org_id, post_id, arrived_at) ON consentvault.raw_post_original_arrival TO consentvault_operator;
GRANT INSERT (from_org, from_post, to_org, to_post) ON consentvault.raw_post_reroute TO consentvault_operator;
CREATE FUNCTION consentvault.record_reroute(p_from_post uuid, p_to_org uuid, p_to_post uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_org  uuid := consentvault.current_org();
    v_from record;
    v_to   record;
BEGIN
    IF v_org IS NULL THEN
        RAISE EXCEPTION 'consentvault reroute refused' USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT rp.received_at, rp.body_sha256 INTO v_from FROM consentvault.raw_post rp
     WHERE rp.org_id OPERATOR(pg_catalog.=) v_org AND rp.post_id OPERATOR(pg_catalog.=) p_from_post;
    SELECT rp.body_sha256, oa.arrived_at INTO v_to
      FROM consentvault.raw_post rp
      JOIN consentvault.raw_post_original_arrival oa ON oa.org_id OPERATOR(pg_catalog.=) rp.org_id AND oa.post_id OPERATOR(pg_catalog.=) rp.post_id
     WHERE rp.org_id OPERATOR(pg_catalog.=) p_to_org AND rp.post_id OPERATOR(pg_catalog.=) p_to_post;
    IF v_from IS NULL OR v_to IS NULL OR v_from.body_sha256 IS DISTINCT FROM v_to.body_sha256
       OR pg_catalog.abs(pg_catalog.date_part('epoch', v_to.arrived_at OPERATOR(pg_catalog.-) v_from.received_at)) OPERATOR(pg_catalog.>) 0.001 THEN
        RAISE EXCEPTION 'consentvault reroute refused' USING ERRCODE = 'insufficient_privilege';
    END IF;
    INSERT INTO consentvault.raw_post_reroute (from_org, from_post, to_org, to_post) VALUES (v_org, p_from_post, p_to_org, p_to_post);
END;
$$;
ALTER FUNCTION consentvault.record_reroute(uuid, uuid, uuid) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.record_reroute(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.record_reroute(uuid, uuid, uuid) TO consentvault_app;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
REVOKE INSERT (from_org, from_post, to_org, to_post) ON consentvault.raw_post_reroute FROM consentvault_app;
