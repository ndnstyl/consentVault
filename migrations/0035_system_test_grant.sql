-- A test push (systems.md) is signed with the system's sealed credential, which the runtime role cannot read by design, and its
-- answer is recorded on the system. Two definer functions do exactly that, for the entered organization and only for a token
-- that holds the admin or developer scope; the runtime role gets no new column right. The limit of 6 a minute per system is
-- counted in the database, so it holds across every server process.
CREATE TABLE consentvault.system_test_attempt (
    org_id    uuid NOT NULL REFERENCES consentvault.organization (org_id),
    system_id uuid NOT NULL,
    at        timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX system_test_attempt_recent ON consentvault.system_test_attempt (system_id, at);
ALTER TABLE consentvault.system_test_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.system_test_attempt FORCE ROW LEVEL SECURITY;
CREATE POLICY system_test_attempt_tenant ON consentvault.system_test_attempt USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
GRANT SELECT ON consentvault.system_test_attempt TO consentvault_app;

-- Begin a test push: counts the last minute, and either says "limited" or records the attempt and returns the target.
CREATE FUNCTION consentvault.system_test_begin(p_system uuid)
    RETURNS TABLE (found boolean, limited boolean, endpoint text, signature text, credentials_ct bytea)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'developer']);
    s   record;
BEGIN
    SELECT c.endpoint, c.signature, c.credentials_ct INTO s FROM consentvault.connected_system c
     WHERE c.system_id = p_system AND c.org_id = org;
    IF NOT FOUND THEN
        RETURN QUERY SELECT false, false, NULL::text, NULL::text, NULL::bytea;
        RETURN;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('consentvault.system_test:' || p_system::text));
    IF (SELECT count(*) FROM consentvault.system_test_attempt a
         WHERE a.system_id = p_system AND a.org_id = org AND a.at > clock_timestamp() - interval '1 minute') >= 6 THEN
        RETURN QUERY SELECT true, true, NULL::text, NULL::text, NULL::bytea;
        RETURN;
    END IF;
    INSERT INTO consentvault.system_test_attempt (org_id, system_id) VALUES (org, p_system);
    RETURN QUERY SELECT true, false, s.endpoint, s.signature, s.credentials_ct;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.system_test_begin(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.system_test_begin(uuid) TO consentvault_app;

-- Record the receiver's answer on the system (a scoped write; the runtime role cannot update the column itself).
CREATE FUNCTION consentvault.system_test_record(p_system uuid, p_answer jsonb) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'developer']);
BEGIN
    UPDATE consentvault.connected_system SET last_test = p_answer WHERE system_id = p_system AND org_id = org;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.system_test_record(uuid, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.system_test_record(uuid, jsonb) TO consentvault_app;
