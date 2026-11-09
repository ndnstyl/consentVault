-- Pure projection, migration step 5 (specs/capture-everything/pure-projection.md, "Migration 0084": renumbered 0086). A fresh database
-- can be loaded with the posts of a store AT THEIR STORED ARRIVAL, so the history can be replayed from empty and compared.
--
-- Today a fresh database refuses a stored arrival: raw_post_received_check (0067) runs check_received_at (0001), which holds a
-- receipt time to one minute of the clock. This migration changes nothing about a live database: the exception is reachable only
-- when ALL of these hold: the database carries the replay mark, the caller is the schema owner itself (that is, inside
-- load_stored_post, whose EXECUTE belongs to the loader role alone), and the session names the post it is loading.
--
-- consentvault_loader is a cluster-wide role the deployment makes (as consentvault_console, migration 0019): this refuses without it.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_loader') THEN
        RAISE EXCEPTION 'consentvault migration 0086 refused: the role consentvault_loader does not exist. As a superuser '
                        '(or the managed database master user) run: CREATE ROLE consentvault_loader NOLOGIN; then apply again.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_loader' AND (rolsuper OR rolbypassrls)) THEN
        RAISE EXCEPTION 'consentvault migration 0086 refused: consentvault_loader must be neither a superuser nor BYPASSRLS';
    END IF;
END
$$;
GRANT USAGE ON SCHEMA consentvault TO consentvault_loader;

-- The replay mark: one row, no row security, append-only. INSERT belongs to the loader alone (nobody reads it directly).
CREATE TABLE consentvault.replay_target (
    only_row  boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    marked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER replay_target_append_only BEFORE UPDATE OR DELETE ON consentvault.replay_target
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER replay_target_no_truncate BEFORE TRUNCATE ON consentvault.replay_target
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();
REVOKE ALL ON consentvault.replay_target FROM PUBLIC;
GRANT INSERT ON consentvault.replay_target TO consentvault_loader;

-- The guard counts raw_post across EVERY organisation, which row security hides from any ordinary role: the function is owned by the
-- operator role (BYPASSRLS) and reads one column of one table, nothing else.
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
GRANT SELECT (post_id) ON consentvault.raw_post TO consentvault_operator;
CREATE FUNCTION consentvault.replay_target_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM consentvault.raw_post) THEN
        RAISE EXCEPTION 'consentvault replay mark refused: this database already holds a post (a store of record is never marked)'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
ALTER FUNCTION consentvault.replay_target_guard() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.replay_target_guard() FROM PUBLIC;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
CREATE TRIGGER replay_target_guard BEFORE INSERT ON consentvault.replay_target
    FOR EACH ROW EXECUTE FUNCTION consentvault.replay_target_guard();

-- True only on a marked database, for the post the session names. The schema owner's definer, so it can read the mark.
CREATE FUNCTION consentvault.loading_allowed(p_post uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM consentvault.replay_target)
       AND p_post IS NOT NULL
       AND coalesce(pg_catalog.current_setting('consentvault.loading_post', true), '') OPERATOR(pg_catalog.=) p_post::pg_catalog.text;
$$;
REVOKE ALL ON FUNCTION consentvault.loading_allowed(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.loading_allowed(uuid) TO consentvault_app, consentvault_console, consentvault_worker, consentvault_loader;

-- Pinned guard, replaced in place (the trigger keeps its name). Not a definer, so current_user is the real caller.
CREATE OR REPLACE FUNCTION consentvault.check_received_at() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    skew pg_catalog.interval := NEW.received_at OPERATOR(pg_catalog.-) pg_catalog.clock_timestamp();
BEGIN
    IF TG_TABLE_NAME OPERATOR(pg_catalog.=) 'raw_post' THEN
        IF current_user OPERATOR(pg_catalog.=) (SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname OPERATOR(pg_catalog.=) 'consentvault') THEN
            IF consentvault.loading_allowed(NEW.post_id) THEN
                RETURN NEW;
            END IF;
        END IF;
    END IF;
    IF skew OPERATOR(pg_catalog.>) '1 minute'::pg_catalog.interval
       OR skew OPERATOR(pg_catalog.<) '-1 minute'::pg_catalog.interval THEN
        RAISE EXCEPTION 'consentvault received_at: the receipt time must be the vault server''s own clock'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- In loader mode the stored fact's computed columns are RECOMPUTED and a row whose stored values differ is refused, so the loaded chain
-- is the stored chain. (Live: unchanged from migration 0082.)
CREATE OR REPLACE FUNCTION consentvault.raw_post_fact_chain() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_max    bigint;
    v_prev   text;
    v_seq    bigint;
    v_digest text;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(NEW.org_id::pg_catalog.text OPERATOR(pg_catalog.||) NEW.post_id::pg_catalog.text, 0));
    -- Loader mode is the replay mark plus the post the session names. This is a definer, so it cannot see its caller; the mark exists
    -- only on a throwaway replay database, which no live database ever carries (the guard on the mark refuses a database with a post).
    IF consentvault.loading_allowed(NEW.post_id) THEN
        IF NEW.fact_sha256 IS NULL THEN
            RETURN NEW;   -- a fact written before migration 0082 loads exactly as stored: no status, no chain
        END IF;
        v_digest := consentvault.fact_digest(NEW.post_id, NEW.fact_id, NEW.fact_seq, NEW.source, NEW.name, NEW.value_ct, NEW.status,
                                             NEW.label, pg_catalog.to_char(NEW.observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                                             NEW.prev_fact_sha256);
        IF v_digest IS DISTINCT FROM NEW.fact_sha256 THEN
            RAISE EXCEPTION 'consentvault load: the stored fact''s hash does not match its columns' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN NEW;
    END IF;
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

-- Loading one stored post and everything stored beside it, at its stored values. One jsonb document (a byte column is the text
-- '\x<hex>'). Refused unless the database carries the replay mark. Posts load in stored seq order: the raw-post chain trigger
-- (0067) still refuses a post that does not extend its head. The caller has entered the post's organisation with a short token.
CREATE FUNCTION consentvault.load_stored_post(p_doc jsonb) RETURNS void
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
REVOKE ALL ON FUNCTION consentvault.load_stored_post(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.load_stored_post(jsonb) TO consentvault_loader;

-- The lookup rows the replay needs byte-equal: the settings, the organisation (its id; home first), its keys and its contact keys.
CREATE FUNCTION consentvault.load_lookup_rows(p_doc jsonb) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM consentvault.replay_target) THEN
        RAISE EXCEPTION 'consentvault load refused: this database carries no replay mark (it is a store of record)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    INSERT INTO consentvault.organization SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.organization, p_doc -> 'organization')
        ON CONFLICT DO NOTHING;
    INSERT INTO consentvault.org_key SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.org_key, p_doc -> 'org_key');
    INSERT INTO consentvault.org_fingerprint_secret SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.org_fingerprint_secret, p_doc -> 'org_fingerprint_secret');
    INSERT INTO consentvault.org_display_key SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.org_display_key, p_doc -> 'org_display_key');
    INSERT INTO consentvault.contact_key SELECT * FROM pg_catalog.jsonb_populate_recordset(NULL::consentvault.contact_key, p_doc -> 'contact_key');
END;
$$;
REVOKE ALL ON FUNCTION consentvault.load_lookup_rows(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.load_lookup_rows(jsonb) TO consentvault_loader;
-- The loader enters one organisation at a time with a short token the fresh database accepts (as the 0076 rebuild job does).
GRANT EXECUTE ON FUNCTION consentvault.enter_org(text) TO consentvault_loader;
