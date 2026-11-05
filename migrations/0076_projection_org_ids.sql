-- The rebuild job of the multi-tenant vault has to name every organisation to project, and no runtime or operator login can read
-- the organisation table without entering one (a run that listed them found none and projected nothing). This returns the
-- organisation ids that are not closed and nothing else (no names, no status): the job then enters each one with its own short
-- token, one at a time. Read-only.
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
CREATE FUNCTION consentvault.projection_org_ids() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT org_id FROM consentvault.organization WHERE status OPERATOR(pg_catalog.<>) 'closed' ORDER BY org_id;
$$;
ALTER FUNCTION consentvault.projection_org_ids() OWNER TO consentvault_operator;   -- the owner the organisation table's grant and policy admit, as active_org_ids
REVOKE ALL ON FUNCTION consentvault.projection_org_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.projection_org_ids() TO consentvault_app;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
