-- Pure projection, migration step 1 (specs/capture-everything/pure-projection.md, "Migration 0080": renumbered 0082 because the
-- one-door branch took 0080 and 0081). A fact carries a status, a label and a place in a chain the DATABASE computes.
--
-- raw_post_fact.value_ct is encrypted and NOT NULL, so no index can see whether a fact is a value, a miss or a failed lookup. This
-- adds columns only: no existing column changes shape, so every seal and every facts_sha256 stays valid. Rows written before this
-- migration keep NULL in all six new columns and are never read by the new fold (the backfill writes their status-bearing copies).
ALTER TABLE consentvault.raw_post_fact
    ADD COLUMN status          text CHECK (status IN ('value', 'not_found', 'not_applicable', 'unparseable', 'lookup_failed', 'lost_race')),
    ADD COLUMN label           text CHECK (label IN ('arrival', 'retry', 'backfill', 'load', 'erased')),
    ADD COLUMN fact_seq        bigint CHECK (fact_seq >= 1),
    ADD COLUMN observed_at     timestamptz,
    ADD COLUMN fact_sha256     text CHECK (fact_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN prev_fact_sha256 text CHECK (prev_fact_sha256 ~ '^[0-9a-f]{64}$');

CREATE UNIQUE INDEX raw_post_fact_seq_key ON consentvault.raw_post_fact (org_id, post_id, fact_seq);
CREATE UNIQUE INDEX raw_post_fact_prev_key ON consentvault.raw_post_fact (org_id, post_id, prev_fact_sha256) WHERE prev_fact_sha256 IS NOT NULL;

-- The digest of one fact: post id, fact id, order, source, name, the ciphertext bytes (so it verifies after the post key is
-- erased), status, label, the database time (as UTC text, microseconds) and the digest before it. A pure function of its arguments.
CREATE FUNCTION consentvault.fact_digest(p_post uuid, p_fact uuid, p_seq bigint, p_source text, p_name text, p_value_ct bytea,
                                         p_status text, p_label text, p_observed text, p_prev text) RETURNS text
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.jsonb_build_array(
        p_post::pg_catalog.text, p_fact::pg_catalog.text, p_seq, p_source, p_name, pg_catalog.encode(p_value_ct, 'hex'), p_status,
        p_label, p_observed, p_prev
    )::pg_catalog.text, 'UTF8')), 'hex');
$$;

-- The database computes the chain (the caller cannot supply a hash or a clock). One writer at a time per post.
CREATE FUNCTION consentvault.raw_post_fact_chain() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_max   bigint;
    v_prev  text;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.org_id::pg_catalog.text OPERATOR(pg_catalog.||) NEW.post_id::pg_catalog.text, 0));
    NEW.observed_at := pg_catalog.clock_timestamp();
    IF NEW.arrival_ordinal IS NOT NULL THEN
        -- an arrival fact: ordered by its ordinal, chained through the post row (its digest is in facts_sha256)
        NEW.fact_seq := NEW.arrival_ordinal OPERATOR(pg_catalog.+) 1;
        NEW.prev_fact_sha256 := NULL;
    ELSE
        SELECT greatest(coalesce(pg_catalog.max(f.fact_seq), 0),
                                   coalesce(pg_catalog.max(f.arrival_ordinal) OPERATOR(pg_catalog.+) 1, 0))
          INTO v_max
          FROM consentvault.raw_post_fact f WHERE f.org_id OPERATOR(pg_catalog.=) NEW.org_id AND f.post_id OPERATOR(pg_catalog.=) NEW.post_id;
        NEW.fact_seq := v_max OPERATOR(pg_catalog.+) 1;
        SELECT f.fact_sha256 INTO v_prev FROM consentvault.raw_post_fact f
         WHERE f.org_id OPERATOR(pg_catalog.=) NEW.org_id AND f.post_id OPERATOR(pg_catalog.=) NEW.post_id
           AND f.arrival_ordinal IS NULL AND f.fact_sha256 IS NOT NULL
         ORDER BY f.fact_seq DESC LIMIT 1;
        IF v_prev IS NULL THEN
            SELECT p.facts_sha256 INTO v_prev FROM consentvault.raw_post p
             WHERE p.org_id OPERATOR(pg_catalog.=) NEW.org_id AND p.post_id OPERATOR(pg_catalog.=) NEW.post_id;
        END IF;
        NEW.prev_fact_sha256 := v_prev;
        -- A second succeeded row of one name lands as lost_race, never as a second answer. Arrival rows are never checked by name.
        IF NEW.label IS DISTINCT FROM 'arrival' AND NEW.label IS DISTINCT FROM 'load'
           AND NEW.status IN ('value', 'not_found', 'not_applicable', 'unparseable')
           AND EXISTS (SELECT 1 FROM consentvault.raw_post_fact f
                        WHERE f.org_id OPERATOR(pg_catalog.=) NEW.org_id AND f.post_id OPERATOR(pg_catalog.=) NEW.post_id
                          AND f.name OPERATOR(pg_catalog.=) NEW.name
                          AND f.status IN ('value', 'not_found', 'not_applicable', 'unparseable')) THEN
            NEW.status := 'lost_race';
        END IF;
    END IF;
    NEW.fact_sha256 := consentvault.fact_digest(NEW.post_id, NEW.fact_id, NEW.fact_seq, NEW.source, NEW.name, NEW.value_ct,
                                                NEW.status, NEW.label,
                                                pg_catalog.to_char(NEW.observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                                                NEW.prev_fact_sha256);
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.raw_post_fact_chain() FROM PUBLIC;
CREATE TRIGGER raw_post_fact_chain BEFORE INSERT ON consentvault.raw_post_fact
    FOR EACH ROW EXECUTE FUNCTION consentvault.raw_post_fact_chain();

-- status and label are the only new columns a caller supplies; the four computed ones are not insertable (as 0067 does for
-- every clock-stamped column).
GRANT INSERT (status, label) ON consentvault.raw_post_fact TO consentvault_app, consentvault_console;
