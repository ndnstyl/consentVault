-- Pure projection, migration step 3 (specs/capture-everything/pure-projection.md, "Migration 0082": renumbered 0084). The history
-- of a person is one row per stored post, holding every value AS SENT: no CHECK on any value, no foreign key to anything a later
-- change could remove. The event table refuses the as-sent history (invalid channel, empty purposes, unregistered wording, a release
-- reference) and is left untouched. The sender's standing (standing) and whether the post is the first copy of its request
-- (earliest_copy) are RECORDED here; they refuse nothing. A fold that writes this table reads facts and the stored post only.
CREATE TABLE consentvault.post_history (
    org_id                     uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    history_seq                bigint NOT NULL,
    post_id                    uuid NOT NULL,
    post_seq                   bigint NOT NULL,
    placed_at                  timestamptz NOT NULL,
    received_at                timestamptz NOT NULL,
    event_id                   uuid NOT NULL,
    label                      text NOT NULL CHECK (label IN ('projected', 'backfill')),
    -- as sent: nothing below is checked against a list, a clock or another table
    event_type_sent            text,
    channels_sent              text[],
    purposes_sent              text[],
    method_sent                text,
    origin_sent                text,
    contact_kind_sent          text,
    captured_at_sent           text,
    wording_sha256_sent        text,
    contact_verification_sent  text,
    source_id_sent             text,
    brand_ids_sent             text[],
    wording_fact_id            uuid,
    -- recorded judgments of the facts, never refusals
    standing                   text NOT NULL,
    earliest_copy              boolean NOT NULL,
    contact_fp                 text,
    contact_key_ref            text,
    completeness               jsonb NOT NULL DEFAULT '{}'::jsonb,
    facts_read                 jsonb NOT NULL DEFAULT '[]'::jsonb,
    rule_set_version           text NOT NULL,
    intake_code_version        text,
    fold_code_version          text NOT NULL,
    contact_ct                 bytea,
    contact_nonce              bytea,
    display_ct                 bytea,
    display_nonce              bytea,
    backfill_of_event_id       uuid,
    prev_hash                  text NOT NULL,
    row_hash                   text NOT NULL,
    hash_version               integer NOT NULL CHECK (hash_version = 3),
    recorded_at                timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, history_seq),
    UNIQUE (org_id, post_id),
    UNIQUE (org_id, event_id),
    UNIQUE (org_id, row_hash),
    FOREIGN KEY (org_id, post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE INDEX post_history_contact_idx ON consentvault.post_history (org_id, contact_fp) WHERE contact_fp IS NOT NULL;
CREATE INDEX post_history_placed_idx ON consentvault.post_history (org_id, placed_at, post_seq);
CREATE TRIGGER post_history_append_only BEFORE UPDATE OR DELETE ON consentvault.post_history
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER post_history_no_truncate BEFORE TRUNCATE ON consentvault.post_history
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- The chain: one writer at a time per organisation (its own advisory lock). The database sets the order, the link and the hash; a
-- projected row's arrival and place must equal the cited post's stored values and its original-arrival row. It reads stored rows,
-- never the clock. A backfill row copies the legacy event's receipt time and is exempt from the arrival check by its label.
CREATE FUNCTION consentvault.post_history_chain() RETURNS trigger
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
REVOKE ALL ON FUNCTION consentvault.post_history_chain() FROM PUBLIC;
CREATE TRIGGER post_history_chain BEFORE INSERT ON consentvault.post_history
    FOR EACH ROW EXECUTE FUNCTION consentvault.post_history_chain();

ALTER TABLE consentvault.post_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.post_history FORCE ROW LEVEL SECURITY;
CREATE POLICY post_history_tenant ON consentvault.post_history USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
CREATE POLICY post_history_read_scope ON consentvault.post_history AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_evidence()));

-- The runtime role appends; the order, the link, the hash and the clock are the database's, not insertable.
GRANT SELECT ON consentvault.post_history TO consentvault_app, consentvault_console, consentvault_integrity;
GRANT INSERT (org_id, post_id, post_seq, placed_at, received_at, event_id, label, event_type_sent, channels_sent, purposes_sent,
              method_sent, origin_sent, contact_kind_sent, captured_at_sent, wording_sha256_sent, contact_verification_sent,
              source_id_sent, brand_ids_sent, wording_fact_id, standing, earliest_copy, contact_fp, contact_key_ref, completeness,
              facts_read, rule_set_version, intake_code_version, fold_code_version, contact_ct, contact_nonce, display_ct,
              display_nonce, backfill_of_event_id, hash_version)
    ON consentvault.post_history TO consentvault_app;
