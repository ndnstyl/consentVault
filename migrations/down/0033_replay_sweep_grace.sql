-- Reverses 0033_replay_sweep_grace.sql: the sweep again removes rows at their expiry.
BEGIN;
CREATE OR REPLACE FUNCTION consentvault.sweep_replay_guard() RETURNS bigint
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    gone bigint;
BEGIN
    DELETE FROM consentvault.replay_guard WHERE expires_at < clock_timestamp();
    GET DIAGNOSTICS gone = ROW_COUNT;
    RETURN gone;
END;
$$;
COMMIT;
