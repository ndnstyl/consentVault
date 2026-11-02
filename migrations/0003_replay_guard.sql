-- Replay guard shared by every vault task: one row per (organisation, nonce) until it expires. A second claim of the
-- same nonce for the same organisation is a replay. Owner-only table, reached through two functions: the runtime
-- role claims nonces, the worker role sweeps expired rows (the only DELETE in the vault besides contact_key).
-- Claims are made before a tenant is entered (a client assertion's jti), so the organisation is an argument here; it
-- comes from consentvault.resolve_credential and the answer says only whether that nonce was seen before.
CREATE TABLE consentvault.replay_guard (
    org_id     uuid NOT NULL REFERENCES consentvault.organization (org_id),
    nonce      text NOT NULL CHECK (length(nonce) BETWEEN 8 AND 200),
    expires_at timestamptz NOT NULL,
    seen_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, nonce)
);
CREATE INDEX replay_guard_expires_idx ON consentvault.replay_guard (expires_at);
REVOKE ALL ON consentvault.replay_guard FROM PUBLIC;

-- true: first sight, recorded. false: replay. Refuses a missing organisation, or an expiry in the past or more than
-- one day ahead (a nonce must not pin a row forever).
CREATE FUNCTION consentvault.claim_replay_nonce(p_org_id uuid, p_nonce text, p_expires_at timestamptz) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    added integer;
BEGIN
    IF p_org_id IS NULL OR p_nonce IS NULL OR p_expires_at IS NULL THEN
        RAISE EXCEPTION 'consentvault replay guard: organisation, nonce and expiry are required'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_expires_at <= clock_timestamp() OR p_expires_at > clock_timestamp() + interval '1 day' THEN
        RAISE EXCEPTION 'consentvault replay guard: expiry must be in the future and within one day'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO consentvault.replay_guard (org_id, nonce, expires_at) VALUES (p_org_id, p_nonce, p_expires_at)
        ON CONFLICT (org_id, nonce) DO NOTHING;
    GET DIAGNOSTICS added = ROW_COUNT;
    -- A row past its expiry that the sweeper has not reached yet still counts as seen: a replay is never let through
    -- because a job ran late.
    RETURN added = 1;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.claim_replay_nonce(uuid, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.claim_replay_nonce(uuid, text, timestamptz) TO consentvault_app;

CREATE FUNCTION consentvault.sweep_replay_guard() RETURNS bigint
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    gone bigint;
BEGIN
    DELETE FROM consentvault.replay_guard WHERE expires_at < clock_timestamp();
    GET DIAGNOSTICS gone = ROW_COUNT;
    RETURN gone;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sweep_replay_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sweep_replay_guard() TO consentvault_worker;
