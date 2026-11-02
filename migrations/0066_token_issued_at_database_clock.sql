-- A tenant token's issued-at is checked against the database's own clock. The minting host stamps iat and exp from its own
-- clock; the database already refuses a token that is expired or lives past fifteen minutes by its clock, but a host running
-- ahead could still mint a token that outlived the lifetime it asked for by its skew. A token stamped more than thirty seconds
-- in the database's future is now refused, so no host clock can lengthen a token's life: it can only get the token refused,
-- loudly, and the database's clock decides every acceptance. A token with no issued-at time (or one that is not a whole number
-- of seconds) is refused too: the mint always stamps one, so its absence means the token was not minted by this service.
CREATE OR REPLACE FUNCTION consentvault.verify_org_token(p_token text)
    RETURNS TABLE (org_id uuid, scopes text[], credential_id text, expires_at timestamptz)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    parts   text[];
    k       bytea;
    want    bytea;
    payload jsonb;
    exp_at  timestamptz;
BEGIN
    IF p_token IS NULL OR length(p_token) > 4096 THEN
        RETURN;
    END IF;
    parts := string_to_array(p_token, '.');
    IF cardinality(parts) <> 4 OR parts[1] <> 'v1' OR parts[2] !~ '^[a-z0-9_-]{1,32}$'
       OR parts[3] !~ '^([0-9a-f]{2})+$' OR parts[4] !~ '^[0-9a-f]{64}$' THEN
        RETURN;
    END IF;
    SELECT secret INTO k FROM consentvault.tenant_token_key WHERE key_id = parts[2] AND retired_at IS NULL;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    want := consentvault.hmac_sha256(k, convert_to('v1.' || parts[2] || '.' || parts[3], 'UTF8'));
    IF sha256(want) <> sha256(decode(parts[4], 'hex')) THEN
        RETURN;
    END IF;
    payload := convert_from(decode(parts[3], 'hex'), 'UTF8')::jsonb;
    exp_at := to_timestamp((payload ->> 'exp')::bigint);
    IF exp_at <= transaction_timestamp() OR exp_at > transaction_timestamp() + interval '15 minutes' THEN
        RETURN;
    END IF;
    -- a token stamped in the future was minted by a host whose clock runs ahead of this database's: refused, never given the
    -- extra life that host's clock would have bought it (a host behind this database mints tokens already expired, also refused)
    IF NOT (payload ? 'iat') OR (payload ->> 'iat') !~ '^[0-9]{1,12}$'
       OR to_timestamp((payload ->> 'iat')::bigint) > statement_timestamp() + interval '30 seconds' THEN
        RETURN;
    END IF;
    org_id := (payload ->> 'org')::uuid;
    scopes := ARRAY(SELECT jsonb_array_elements_text(payload -> 'scp'));
    credential_id := payload ->> 'cid';
    expires_at := exp_at;
    RETURN NEXT;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.verify_org_token(text) FROM PUBLIC;
