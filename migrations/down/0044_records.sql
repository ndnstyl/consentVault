-- Reverses 0044_records.sql. Run it as a superuser (the trigger guard refuses changes to pinned guards for anyone else), in
-- one transaction. Drops the record tables and the display key; the functions this migration redefined (erase_contact, the key
-- version census, the secret re-wrap) go back to their 0014 and 0020 shapes. The pins of the objects dropped here are cleared;
-- a superuser re-pins after the next migration run. Names and companies held in record_display are deleted with the table.
BEGIN;

DO $$
BEGIN
    IF to_regclass('consentvault.record_index') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0044 refused: 0044 is not applied';
    END IF;
    IF to_regclass('consentvault_guard.pin') IS NOT NULL THEN
        DELETE FROM consentvault_guard.pin WHERE identity IN ('consentvault.record_guard()', 'consentvault.org_display_key_guard()',
            'record_guard on consentvault.record', 'record_no_truncate on consentvault.record',
            'org_display_key_append_only on consentvault.org_display_key',
            'org_display_key_no_truncate on consentvault.org_display_key');
    END IF;
    IF to_regclass('consentvault_guard.table_pin') IS NOT NULL THEN
        DELETE FROM consentvault_guard.table_pin WHERE rel IN ('consentvault.record'::regclass,
            'consentvault.org_display_key'::regclass, 'consentvault.record_index'::regclass,
            'consentvault.record_display'::regclass);
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION consentvault.erase_contact(p_contact_fp text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.lifecycle_lock();
    h   uuid;
    n   integer;
BEGIN
    IF p_contact_fp IS NULL OR p_contact_fp !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'consentvault erase: the fingerprint must be 64 hex characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF NOT coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'worker:restore'], false) THEN
        RAISE EXCEPTION 'consentvault erase: an admin or restore token is required' USING ERRCODE = 'insufficient_privilege';
    END IF;
    h := consentvault.legal_hold_covering(p_contact_fp);
    IF h IS NOT NULL THEN
        RAISE EXCEPTION 'legal_hold_active:%', h USING ERRCODE = 'integrity_constraint_violation',
            DETAIL = 'a legal hold covers this contact; its key is not deleted';
    END IF;
    DELETE FROM consentvault.contact_key k WHERE k.org_id = org AND k.contact_fp = p_contact_fp;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n > 0;
END;
$$;

CREATE OR REPLACE FUNCTION consentvault.key_version_census_of(p_org uuid, p_version integer) RETURNS TABLE (kind text, n bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT 'contact_key', count(*) FROM consentvault.contact_key WHERE org_id = p_org AND key_version = p_version
    UNION ALL
    SELECT 'fingerprint_secret', count(*) FROM consentvault.org_fingerprint_secret
     WHERE org_id = p_org AND consentvault.wrap_version(wrapped) = p_version
    UNION ALL
    SELECT 'credential', count(*) FROM consentvault.credential
     WHERE org_id = p_org AND secret_ct IS NOT NULL AND consentvault.wrap_version(secret_ct) = p_version
    UNION ALL
    SELECT 'connected_system', count(*) FROM consentvault.connected_system
     WHERE org_id = p_org AND credentials_ct IS NOT NULL AND consentvault.wrap_version(credentials_ct) = p_version
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
    ELSIF p_kind = 'credential' THEN
        UPDATE consentvault.credential SET secret_ct = p_new
         WHERE org_id = org AND credential_id = p_ref AND secret_ct = p_old;
    ELSIF p_kind = 'connected_system' THEN
        UPDATE consentvault.connected_system SET credentials_ct = p_new
         WHERE org_id = org AND system_id = p_ref AND credentials_ct = p_old;
    ELSE
        PERFORM set_config('consentvault.rewrap', 'off', true);
        RAISE EXCEPTION 'consentvault re-wrap refused: unknown secret kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('consentvault.rewrap', 'off', true);
    RETURN n = 1;
END;
$$;

DROP FUNCTION consentvault.record_reveal_note(text, uuid[], timestamptz);
DROP FUNCTION consentvault.record_call_take(text, timestamptz, integer, integer);
DROP TABLE consentvault.record_reveal_log;
DROP TABLE consentvault.record_call;
DROP FUNCTION consentvault.record_index_rebuild(uuid);
DROP FUNCTION consentvault.record_index_set_confirmation(uuid, text, text, timestamptz);
DROP FUNCTION consentvault.record_display_write(uuid, bytea, bytea);
DROP FUNCTION consentvault.record_index_refresh(uuid, text, bytea);
DROP FUNCTION consentvault.record_upsert(uuid, text, text);
DROP FUNCTION consentvault.record_index_derive(uuid, uuid, bytea);

DROP TABLE consentvault.record_display;
DROP TABLE consentvault.record_index;
DROP TABLE consentvault.record;
DROP TABLE consentvault.org_display_key;
DROP FUNCTION consentvault.record_guard();
DROP FUNCTION consentvault.org_display_key_guard();
DROP FUNCTION consentvault.may_read_names();
DROP FUNCTION consentvault.may_read_records();
ALTER TABLE consentvault.organization DROP COLUMN default_region;
DROP FUNCTION consentvault.may_read_display_key();
COMMIT;
