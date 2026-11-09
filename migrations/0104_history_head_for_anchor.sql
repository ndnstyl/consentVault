-- Pure projection, item 33: the anchor job holds a worker's token, which carries no evidence read scope, so it cannot read the history head
-- through the invoker view of it. This is ledger_head()'s counterpart: a definer that answers the entered organisation's newest history
-- row (sequence number and hash, no personal field) whatever scope the token carries.
CREATE FUNCTION consentvault.history_head_entered() RETURNS TABLE (seq bigint, row_hash text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT h.history_seq, h.row_hash FROM consentvault.post_history h
     WHERE h.org_id OPERATOR(pg_catalog.=) consentvault.current_org() ORDER BY h.history_seq DESC LIMIT 1;
$$;
REVOKE ALL ON FUNCTION consentvault.history_head_entered() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.history_head_entered() TO consentvault_app, consentvault_worker, consentvault_integrity;
