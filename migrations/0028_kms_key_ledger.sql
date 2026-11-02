-- The record a cloud key provider keeps of the destructions it scheduled (key ids, dates, destroyed versions). KMS
-- forgets a key once it deletes it, so this record is what lets the destruction job report a deleted key as destroyed;
-- it lives here, never on a task's disk.
--
-- Platform table: owner-only, row security forced with no policy, so no login reads or writes it directly. The two
-- functions below are owned by consentvault_operator (as append_platform_audit is): the operator console, which runs
-- onboarding and the key-lifecycle job, writes; the runtime and worker logins read, so the data path can tell a
-- destroyed key from a missing one.

CREATE TABLE consentvault.kms_key_ledger (
    org_ref    text PRIMARY KEY CHECK (org_ref ~ '^[A-Za-z0-9_-]{1,64}$'),
    entry      jsonb NOT NULL CHECK (jsonb_typeof(entry) = 'object'),
    updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE consentvault.kms_key_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.kms_key_ledger FORCE ROW LEVEL SECURITY;
REVOKE ALL ON consentvault.kms_key_ledger FROM PUBLIC;
-- Only the functions' owner (the NOLOGIN operator role) touches the table.
GRANT SELECT, INSERT, UPDATE ON consentvault.kms_key_ledger TO consentvault_operator;

-- The operator role may own the two functions only while this migration runs (as 0005, 0007, 0011 and 0014 do).
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;

CREATE FUNCTION consentvault.kms_key_ledger_read()
    RETURNS TABLE (org_ref text, entry jsonb)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RETURN QUERY SELECT l.org_ref, l.entry FROM consentvault.kms_key_ledger l ORDER BY l.org_ref;
END;
$$;
ALTER FUNCTION consentvault.kms_key_ledger_read() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.kms_key_ledger_read() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.kms_key_ledger_read() TO consentvault_console, consentvault_app,
    consentvault_worker;

-- A destruction is never undone through here: a write that drops or changes a recorded destroyed_at, or drops a
-- version recorded as destroyed, is refused. Adding to the record is always allowed.
CREATE FUNCTION consentvault.kms_key_ledger_write(p_org text, p_entry jsonb) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    held jsonb;
BEGIN
    IF p_org IS NULL OR p_org !~ '^[A-Za-z0-9_-]{1,64}$' OR p_entry IS NULL OR jsonb_typeof(p_entry) <> 'object' THEN
        RAISE EXCEPTION 'consentvault key ledger: an org reference and a JSON object entry are required'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT l.entry INTO held FROM consentvault.kms_key_ledger l WHERE l.org_ref = p_org FOR UPDATE;
    IF FOUND THEN
        IF coalesce(held -> 'destroyed_at', 'null'::jsonb) <> 'null'::jsonb
           AND (p_entry -> 'destroyed_at') IS DISTINCT FROM (held -> 'destroyed_at') THEN
            RAISE EXCEPTION 'consentvault key ledger: org % was recorded destroyed at %; that is never changed',
                p_org, held ->> 'destroyed_at' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        IF NOT (coalesce(p_entry -> 'destroyed_versions', '[]'::jsonb) @> coalesce(held -> 'destroyed_versions', '[]'::jsonb)) THEN
            RAISE EXCEPTION 'consentvault key ledger: a destroyed version of org % would be dropped from the record', p_org
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    INSERT INTO consentvault.kms_key_ledger (org_ref, entry) VALUES (p_org, p_entry)
        ON CONFLICT (org_ref) DO UPDATE SET entry = excluded.entry, updated_at = now();
END;
$$;
ALTER FUNCTION consentvault.kms_key_ledger_write(text, jsonb) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.kms_key_ledger_write(text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.kms_key_ledger_write(text, jsonb) TO consentvault_console;

REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
