-- The replay guard keeps a nonce for an hour after it expires. A nonce expires at the last moment the request that carried
-- it would still be accepted (the signature window); a sweep that deleted it at that instant would let a process whose
-- clock runs behind accept the same signed request again. The sweep now removes only rows expired more than an hour ago.
CREATE OR REPLACE FUNCTION consentvault.sweep_replay_guard() RETURNS bigint
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    gone bigint;
BEGIN
    DELETE FROM consentvault.replay_guard WHERE expires_at < clock_timestamp() - interval '1 hour';
    GET DIAGNOSTICS gone = ROW_COUNT;
    RETURN gone;
END;
$$;
