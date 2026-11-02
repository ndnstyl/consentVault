-- Key rotation learns the sending-account secrets (confirmations.md section 13): the provider secret and the Twilio auth token are
-- wrapped by the organization key, so the census counts them under 'sending_account' and the re-wrap moves them (a compare-and-swap
-- on the old value, like every other secret). The operator console, which runs the re-wrap, may read just those two columns.
-- (The other sealed columns of the confirmation tables are sealed under the display key, which rotates already.)

CREATE OR REPLACE FUNCTION consentvault.key_version_census_of(p_org uuid, p_version integer) RETURNS TABLE (kind text, n bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT 'contact_key', count(*) FROM consentvault.contact_key WHERE org_id = p_org AND key_version = p_version
    UNION ALL
    SELECT 'fingerprint_secret', count(*) FROM consentvault.org_fingerprint_secret
     WHERE org_id = p_org AND consentvault.wrap_version(wrapped) = p_version
    UNION ALL
    SELECT 'display_key', count(*) FROM consentvault.org_display_key
     WHERE org_id = p_org AND consentvault.wrap_version(wrapped) = p_version
    UNION ALL
    SELECT 'credential', count(*) FROM consentvault.credential
     WHERE org_id = p_org AND secret_ct IS NOT NULL AND consentvault.wrap_version(secret_ct) = p_version
    UNION ALL
    SELECT 'connected_system', count(*) FROM consentvault.connected_system
     WHERE org_id = p_org AND credentials_ct IS NOT NULL AND consentvault.wrap_version(credentials_ct) = p_version
    UNION ALL
    SELECT 'sending_account', count(*) FROM consentvault.sending_account a
     WHERE a.org_id = p_org AND ((a.credentials_ct IS NOT NULL AND consentvault.wrap_version(a.credentials_ct) = p_version)
                                 OR (a.auth_token_ct IS NOT NULL AND consentvault.wrap_version(a.auth_token_ct) = p_version))
    UNION ALL
    SELECT 'final_export', count(*) FROM consentvault.offboarding_request
     WHERE org_id = p_org AND final_export_wrapped IS NOT NULL AND consentvault.wrap_version(final_export_wrapped) = p_version
    UNION ALL
    SELECT 'hold_reason', count(*) FROM consentvault.legal_hold
     WHERE org_id = p_org AND (consentvault.sealed_version(reason) = p_version
                               OR consentvault.sealed_version(release_reason) = p_version);
$$;

CREATE OR REPLACE FUNCTION consentvault.rewrap_org_secret(p_kind text, p_ref uuid, p_old bytea, p_new bytea) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.current_org();
    n   integer;
BEGIN
    PERFORM consentvault.rewrap_target_ok(org, consentvault.wrap_version(p_new));
    IF p_old IS NULL OR consentvault.wrap_version(p_new) <= consentvault.wrap_version(p_old) THEN
        RAISE EXCEPTION 'consentvault re-wrap refused: a secret moves to a newer key version'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM set_config('consentvault.rewrap', 'on', true);
    IF p_kind = 'fingerprint_secret' THEN
        UPDATE consentvault.org_fingerprint_secret SET wrapped = p_new WHERE org_id = org AND wrapped = p_old;
    ELSIF p_kind = 'display_key' THEN
        UPDATE consentvault.org_display_key SET wrapped = p_new, key_version = consentvault.wrap_version(p_new)
         WHERE org_id = org AND wrapped = p_old;
    ELSIF p_kind = 'credential' THEN
        UPDATE consentvault.credential SET secret_ct = p_new
         WHERE org_id = org AND credential_id = p_ref AND secret_ct = p_old;
    ELSIF p_kind = 'connected_system' THEN
        UPDATE consentvault.connected_system SET credentials_ct = p_new
         WHERE org_id = org AND system_id = p_ref AND credentials_ct = p_old;
    ELSIF p_kind = 'sending_credentials' THEN
        UPDATE consentvault.sending_account SET credentials_ct = p_new
         WHERE org_id = org AND account_id = p_ref AND credentials_ct = p_old;
    ELSIF p_kind = 'sending_auth_token' THEN
        UPDATE consentvault.sending_account SET auth_token_ct = p_new
         WHERE org_id = org AND account_id = p_ref AND auth_token_ct = p_old;
    ELSE
        PERFORM set_config('consentvault.rewrap', 'off', true);
        RAISE EXCEPTION 'consentvault re-wrap refused: unknown secret kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('consentvault.rewrap', 'off', true);
    RETURN n = 1;
END;
$$;

GRANT SELECT (org_id, account_id, credentials_ct, auth_token_ct) ON consentvault.sending_account TO consentvault_console;
