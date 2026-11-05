-- A single-company vault's own contact fingerprint secret: made once on first use (the caller supplies 32 random bytes and the
-- first writer wins), read back by the match writer. One row, never updated or deleted. A multi-tenant vault keeps each
-- organisation's secret with its key provider and never reads this table.
CREATE TABLE consentvault.single_fingerprint_secret (
    singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    secret     bytea NOT NULL CHECK (octet_length(secret) >= 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER single_fingerprint_secret_append_only BEFORE UPDATE OR DELETE ON consentvault.single_fingerprint_secret
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER single_fingerprint_secret_no_truncate BEFORE TRUNCATE ON consentvault.single_fingerprint_secret
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();
ALTER TABLE consentvault.single_fingerprint_secret ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.single_fingerprint_secret FORCE ROW LEVEL SECURITY;
-- no login holds a grant on the table; only the definer function below reaches it, so the one policy admits the owner's own statements
CREATE POLICY single_fingerprint_secret_owner ON consentvault.single_fingerprint_secret USING (true) WITH CHECK (true);
REVOKE ALL ON consentvault.single_fingerprint_secret FROM PUBLIC;

CREATE FUNCTION consentvault.single_fingerprint_secret(p_new bytea) RETURNS bytea
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    s pg_catalog.bytea;
BEGIN
    IF (SELECT t.mode FROM consentvault.tenancy_setting t WHERE t.singleton) OPERATOR(pg_catalog.<>) 'single' THEN
        RAISE EXCEPTION 'consentvault single_fingerprint_secret: this vault is multi-tenant; each organisation has its own secret'
            USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    INSERT INTO consentvault.single_fingerprint_secret (secret) VALUES (p_new) ON CONFLICT DO NOTHING;
    SELECT f.secret INTO s FROM consentvault.single_fingerprint_secret f;
    RETURN s;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.single_fingerprint_secret(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.single_fingerprint_secret(bytea) TO consentvault_app;
