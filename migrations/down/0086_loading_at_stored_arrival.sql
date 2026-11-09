-- Reverses 0086_loading_at_stored_arrival.sql: the loader functions, the replay mark and its guard are dropped; check_received_at is
-- the migration 0001 function again and the fact chain trigger function is the migration 0082 one. On the pinned guards this runs as
-- the superuser followed by consentvault_guard.repin(), exactly as 0068 and 0071 did. No post or fact is touched.
BEGIN;
DROP FUNCTION consentvault.load_lookup_rows(jsonb);
DROP FUNCTION consentvault.load_stored_post(jsonb);
CREATE OR REPLACE FUNCTION consentvault.check_received_at() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    skew pg_catalog.interval := NEW.received_at OPERATOR(pg_catalog.-) pg_catalog.clock_timestamp();
BEGIN
    IF skew OPERATOR(pg_catalog.>) '1 minute'::pg_catalog.interval
       OR skew OPERATOR(pg_catalog.<) '-1 minute'::pg_catalog.interval THEN
        RAISE EXCEPTION 'consentvault received_at: the receipt time must be the vault server''s own clock'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION consentvault.raw_post_fact_chain() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_max   bigint;
    v_prev  text;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.org_id::pg_catalog.text OPERATOR(pg_catalog.||) NEW.post_id::pg_catalog.text, 0));
    NEW.observed_at := pg_catalog.clock_timestamp();
    IF NEW.arrival_ordinal IS NOT NULL THEN
        NEW.fact_seq := NEW.arrival_ordinal OPERATOR(pg_catalog.+) 1;
        NEW.prev_fact_sha256 := NULL;
    ELSE
        SELECT greatest(coalesce(pg_catalog.max(f.fact_seq), 0), coalesce(pg_catalog.max(f.arrival_ordinal) OPERATOR(pg_catalog.+) 1, 0))
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
DROP TRIGGER replay_target_guard ON consentvault.replay_target;
DROP FUNCTION consentvault.replay_target_guard();
DROP FUNCTION consentvault.loading_allowed(uuid);
DROP TABLE consentvault.replay_target;
REVOKE SELECT (post_id) ON consentvault.raw_post FROM consentvault_operator;
COMMIT;
