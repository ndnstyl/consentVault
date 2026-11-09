-- Pure projection, migration step 8 (specs/capture-everything/pure-projection.md, "Migration 0086": renumbered 0088). Every retrieval of
-- the record (an evidence export, a proof, a contact check, a post read, a receipt) is logged with who, when (the database clock)
-- and what was returned, chained per organisation, so the record can show that what it hands over is what it holds (gate 4).
-- The log row is written in the read's transaction by the reader; a read whose log row cannot be written returns nothing and raises.
CREATE TABLE consentvault.retrieval_log (
    org_id         uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    retrieval_id   bigint NOT NULL,
    actor_kind     text NOT NULL,
    actor_id       text NOT NULL,
    at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    what           jsonb NOT NULL,   -- the history or post ids the read returned
    payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    prev_hash      text NOT NULL,
    row_hash       text NOT NULL,
    PRIMARY KEY (org_id, retrieval_id)
);
CREATE TRIGGER retrieval_log_append_only BEFORE UPDATE OR DELETE ON consentvault.retrieval_log
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER retrieval_log_no_truncate BEFORE TRUNCATE ON consentvault.retrieval_log
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

CREATE FUNCTION consentvault.retrieval_log_chain() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_head record;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('retrieval_log' OPERATOR(pg_catalog.||) NEW.org_id::pg_catalog.text, 0));
    SELECT l.retrieval_id, l.row_hash INTO v_head FROM consentvault.retrieval_log l
     WHERE l.org_id OPERATOR(pg_catalog.=) NEW.org_id ORDER BY l.retrieval_id DESC LIMIT 1;
    NEW.retrieval_id := coalesce(v_head.retrieval_id, 0) OPERATOR(pg_catalog.+) 1;
    NEW.prev_hash := coalesce(v_head.row_hash, pg_catalog.repeat('0', 64));
    NEW.at := pg_catalog.clock_timestamp();
    NEW.row_hash := pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
        NEW.prev_hash OPERATOR(pg_catalog.||) ((pg_catalog.to_jsonb(NEW) OPERATOR(pg_catalog.-) 'row_hash'::pg_catalog.text
                                                OPERATOR(pg_catalog.-) 'prev_hash'::pg_catalog.text)::pg_catalog.text), 'UTF8')), 'hex');
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.retrieval_log_chain() FROM PUBLIC;
CREATE TRIGGER retrieval_log_chain BEFORE INSERT ON consentvault.retrieval_log
    FOR EACH ROW EXECUTE FUNCTION consentvault.retrieval_log_chain();

ALTER TABLE consentvault.retrieval_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.retrieval_log FORCE ROW LEVEL SECURITY;
CREATE POLICY retrieval_log_tenant ON consentvault.retrieval_log USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
CREATE POLICY retrieval_log_read_scope ON consentvault.retrieval_log AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_evidence()));

-- The order, the link, the hash and the clock are the database's: not insertable.
GRANT SELECT ON consentvault.retrieval_log TO consentvault_app, consentvault_console, consentvault_integrity;
GRANT INSERT (org_id, actor_kind, actor_id, what, payload_sha256) ON consentvault.retrieval_log TO consentvault_app, consentvault_console;
