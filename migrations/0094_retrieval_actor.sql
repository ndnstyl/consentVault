-- Pure projection, gate 4 (specs/capture-everything/pure-projection.md, item 31). A retrieval is logged under the caller that made it. The
-- credential id rides inside the tenant token the database already verifies; this returns it for the current transaction, and NULL when
-- the transaction was entered with no token (a process in single mode, which the log then names by its database login).
CREATE FUNCTION consentvault.current_token_credential() RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT v.credential_id FROM consentvault.verify_org_token(
        nullif(pg_catalog.current_setting('consentvault.org_token', true), '')) v;
$$;
REVOKE ALL ON FUNCTION consentvault.current_token_credential() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.current_token_credential() TO consentvault_app, consentvault_worker, consentvault_console;
