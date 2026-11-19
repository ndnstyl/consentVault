-- The state of one channel for one contact, for the push body: denied while ANY purpose on that channel is denied, else permitted,
-- with a version that is the sum of that channel's per-purpose versions. Each per-purpose version only ever grows, so the sum never
-- decreases, and a receiver that keeps one field per channel can gate grants on it (a stop is always applied).
-- Read-only; reads state_version through owner rights because the runtime role has no table privilege on it (same as 0004).
CREATE FUNCTION consentvault.sync_channel_state(p_contact_fp text, p_channel text)
    RETURNS TABLE (channel_state text, channel_version integer)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
BEGIN
    RETURN QUERY
    SELECT CASE WHEN coalesce(bool_or(sv.state = 'denied'), false) THEN 'denied' ELSE 'permitted' END,
           coalesce(sum(sv.version), 0)::integer
      FROM consentvault.state_version sv
     WHERE sv.org_id = org AND sv.contact_fp = p_contact_fp AND sv.channel = p_channel;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_channel_state(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_channel_state(text, text) TO consentvault_app;
-- The console records stops too (erasure, restore re-ingest) through the same hook, as in 0019: it needs the same reader.
GRANT EXECUTE ON FUNCTION consentvault.sync_channel_state(text, text) TO consentvault_console;
