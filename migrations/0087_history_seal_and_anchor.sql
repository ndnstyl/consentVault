-- Pure projection, migration step 8 (specs/capture-everything/pure-projection.md, "Migration 0085": renumbered 0087). The history chain
-- is sealed and anchored like the raw-post chain (gate 7): post_history_seal is shaped as raw_post_seal (0067) and names the exact
-- column list its digest covers, so a column added later never touches an existing seal (the consent-evidence rule);
-- post_history_chain_head is shaped as raw_post_chain_head (0067), the anchors of the history chain.
CREATE TABLE consentvault.post_history_seal (
    seal_uuid    uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id       uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    history_seq  bigint NOT NULL,
    hash_version integer NOT NULL,
    columns      text[] NOT NULL,
    digest       bytea NOT NULL CHECK (octet_length(digest) = 32),
    tsa_url      text NOT NULL,
    token        bytea NOT NULL,
    gen_time     timestamptz,
    verified_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, history_seq) REFERENCES consentvault.post_history (org_id, history_seq)
);
CREATE INDEX post_history_seal_row_idx ON consentvault.post_history_seal (org_id, history_seq);

CREATE FUNCTION consentvault.post_history_seal_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.post_history_seal is append-only: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (pg_catalog.to_jsonb(NEW) OPERATOR(pg_catalog.-) 'verified_at'::pg_catalog.text)
           IS DISTINCT FROM (pg_catalog.to_jsonb(OLD) OPERATOR(pg_catalog.-) 'verified_at'::pg_catalog.text) THEN
        RAISE EXCEPTION 'consentvault.post_history_seal is append-only: only verified_at may change'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER post_history_seal_guard BEFORE UPDATE OR DELETE ON consentvault.post_history_seal
    FOR EACH ROW EXECUTE FUNCTION consentvault.post_history_seal_guard();
CREATE TRIGGER post_history_seal_no_truncate BEFORE TRUNCATE ON consentvault.post_history_seal
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

CREATE FUNCTION consentvault.mark_post_history_seal_verified(p_seal_uuid uuid) RETURNS void
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    UPDATE consentvault.post_history_seal SET verified_at = pg_catalog.clock_timestamp()
     WHERE seal_uuid OPERATOR(pg_catalog.=) p_seal_uuid AND org_id OPERATOR(pg_catalog.=) consentvault.current_org()
       AND verified_at IS NULL;
$$;
REVOKE ALL ON FUNCTION consentvault.mark_post_history_seal_verified(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.mark_post_history_seal_verified(uuid) TO consentvault_app, consentvault_integrity;

CREATE TABLE consentvault.post_history_chain_head (
    head_uuid   uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id      uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    seq         bigint NOT NULL CHECK (seq >= 1),
    row_hash    text NOT NULL CHECK (row_hash ~ '^[0-9a-f]{64}$'),
    sink        text,
    anchored_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER post_history_chain_head_append_only BEFORE UPDATE OR DELETE ON consentvault.post_history_chain_head
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER post_history_chain_head_no_truncate BEFORE TRUNCATE ON consentvault.post_history_chain_head
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['post_history_seal', 'post_history_chain_head'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I AS RESTRICTIVE FOR SELECT USING ((SELECT consentvault.may_read_evidence()))',
                       t || '_read_scope', t);
    END LOOP;
END
$$;

GRANT SELECT, INSERT ON consentvault.post_history_seal, consentvault.post_history_chain_head TO consentvault_app, consentvault_integrity;
GRANT SELECT ON consentvault.post_history_seal, consentvault.post_history_chain_head TO consentvault_console;
