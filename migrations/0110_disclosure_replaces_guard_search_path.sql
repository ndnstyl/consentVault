-- The wording replaces-link guard (0092) is created without a pinned search path; every function in the schema pins
-- search_path = pg_catalog, pg_temp, so a caller's search path can never change what its names resolve to. Its body qualifies every
-- table and type it reads, so pinning changes no behaviour. A new file, never an edit of the applied 0092.
ALTER FUNCTION consentvault.disclosure_replaces_guard() SET search_path = pg_catalog, pg_temp;
