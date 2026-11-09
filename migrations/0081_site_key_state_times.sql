-- When a site key was revoked and when its capture source was retired, so a post is judged by the state its key was in when the post
-- ARRIVED and not by the state it is in when the projection runs (one-door review round 5). resolve_site_key answers only the
-- state now; this answers the two times behind it, for one key at a time, like resolve_site_key: one row or none, never a list.
GRANT SELECT (retired_at) ON consentvault.capture_source TO consentvault_operator;

CREATE FUNCTION consentvault.resolve_site_key_times(p_site_key text)
    RETURNS TABLE (revoked_at timestamptz, source_retired_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT c.revoked_at, s.retired_at
    FROM consentvault.credential c
    JOIN consentvault.capture_source s ON s.org_id = c.org_id AND s.source_id = c.source_id
    WHERE p_site_key ~ '^cv_site_[A-Za-z0-9_-]{16,64}$'
      AND c.site_key_hash = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_site_key, 'UTF8')), 'hex');
$$;
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
ALTER FUNCTION consentvault.resolve_site_key_times(text) OWNER TO consentvault_operator;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.resolve_site_key_times(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.resolve_site_key_times(text) TO consentvault_app;
