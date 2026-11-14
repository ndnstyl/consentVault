-- Reverses 0057_token_expiry_at_transaction_start.sql: a tenant token's expiry is judged at each statement again.
BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                   WHERE n.nspname = 'consentvault' AND p.proname = 'verify_org_token'
                     AND p.prosrc LIKE '%transaction_timestamp()%') THEN
        RAISE EXCEPTION 'consentvault down 0057 refused: 0057 is not applied';
    END IF;
END
$$;

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
    IF exp_at <= statement_timestamp() OR exp_at > statement_timestamp() + interval '15 minutes' THEN
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

COMMIT;
