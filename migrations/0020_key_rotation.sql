-- Per-organisation key rotation (spec FR-011: rotation per tenant, without re-signing or re-chaining history, every key
-- operation audited).
--
-- An organisation key has versions (consentvault.org_key, one row per version). A rotation makes a new version the
-- active one: every contact key written from then on is wrapped under it, and the operator job re-wraps every existing
-- contact key and every other value the organisation key wraps (the fingerprint secret, credential secrets, connected
-- system credentials, the sealed reasons of holds) under the new version, in batches. The data keys themselves never
-- change, so no ciphertext, event row, chain link, seal or anchor is touched. The old version is destroyed only when
-- nothing in the database is wrapped under it any more, and never while a legal hold of the organisation is active.
--
-- * key_rotation: one row per rotation, its state visible to the operator (rewrapping, blocked with a named reason,
--   complete). At most one open rotation per organisation.
-- * A contact key, the fingerprint secret and a hold's reason change only through the owner functions below
--   (rewrap_contact_key, rewrap_org_secret, rewrap_hold_reason), each a compare-and-swap on the old value, so a replayed
--   or concurrent re-wrap is a no-op. Every other change stays refused.
-- * key_version_census(version) counts what is still wrapped under a version; org_key_version_guard refuses to mark a
--   retired version destroyed while that count is not zero, and contact_key_version_guard refuses a contact key written
--   under a destroyed version (it waits on the destroying transaction, so none slips in between the count and the
--   destruction).
-- * A wrap made under version 2 or later starts with 'CVKV' and its version (4 bytes, big endian); a version-1 wrap has
--   no header (providers.keys.wrapped_version). wrap_version() reads it the same way.

-- 1. Reading the version a value is wrapped under ---------------------------------------------------------------------------
CREATE FUNCTION consentvault.wrap_version(p bytea) RETURNS integer
    LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN octet_length(p) > 8 AND substring(p FROM 1 FOR 4) = '\x43564b56'::bytea
                THEN ((get_byte(p, 4)::bigint << 24) | (get_byte(p, 5) << 16) | (get_byte(p, 6) << 8) | get_byte(p, 7))::integer
                ELSE 1 END;
$$;

-- A hold's sealed reason ('ocv1:' + urlsafe base64 of: wrapped length (2 bytes), key version (4 bytes), wrapped, field).
CREATE FUNCTION consentvault.sealed_version(p text) RETURNS integer
    LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN left(p, 5) = 'ocv1:'
                THEN (SELECT ((get_byte(b, 2)::bigint << 24) | (get_byte(b, 3) << 16) | (get_byte(b, 4) << 8)
                              | get_byte(b, 5))::integer
                        FROM (SELECT decode(translate(substr(p, 6), '-_', '+/'), 'base64') AS b) x)
                END;
$$;

-- 2. What is still wrapped under one version of one organisation's key ------------------------------------------------------
CREATE FUNCTION consentvault.key_version_census_of(p_org uuid, p_version integer) RETURNS TABLE (kind text, n bigint)
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
REVOKE ALL ON FUNCTION consentvault.key_version_census_of(uuid, integer) FROM PUBLIC;

CREATE FUNCTION consentvault.key_version_census(p_version integer) RETURNS TABLE (kind text, n bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT c.kind, c.n FROM consentvault.key_version_census_of(consentvault.current_org(), p_version) c
     WHERE consentvault.current_org() IS NOT NULL;
$$;
REVOKE ALL ON FUNCTION consentvault.key_version_census(integer) FROM PUBLIC;

-- 3. Rotations ---------------------------------------------------------------------------------------------------------------
CREATE TABLE consentvault.key_rotation (
    org_id         uuid NOT NULL REFERENCES consentvault.organization (org_id),
    rotation_id    uuid NOT NULL DEFAULT gen_random_uuid(),
    from_version   integer NOT NULL CHECK (from_version >= 1),
    to_version     integer NOT NULL,
    reason         text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    started_by     text NOT NULL CHECK (length(started_by) BETWEEN 1 AND 200),
    started_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    status         text NOT NULL DEFAULT 'rewrapping' CHECK (status IN ('rewrapping', 'blocked', 'complete')),
    blocked_reason text CHECK (blocked_reason IS NULL OR length(blocked_reason) BETWEEN 1 AND 500),
    rewrapped      integer NOT NULL DEFAULT 0 CHECK (rewrapped >= 0),
    batches        integer NOT NULL DEFAULT 0 CHECK (batches >= 0),
    last_batch_at  timestamptz,
    completed_at   timestamptz,
    PRIMARY KEY (org_id, rotation_id),
    FOREIGN KEY (org_id, from_version) REFERENCES consentvault.org_key (org_id, version),
    FOREIGN KEY (org_id, to_version) REFERENCES consentvault.org_key (org_id, version),
    CONSTRAINT key_rotation_next_version CHECK (to_version = from_version + 1),
    CONSTRAINT key_rotation_blocked_shape CHECK ((status = 'blocked') = (blocked_reason IS NOT NULL)),
    CONSTRAINT key_rotation_complete_shape CHECK ((status = 'complete') = (completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX key_rotation_one_open_idx ON consentvault.key_rotation (org_id) WHERE status <> 'complete';

CREATE FUNCTION consentvault.key_rotation_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.key_rotation is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status = 'complete' THEN
        RAISE EXCEPTION 'consentvault.key_rotation: a complete rotation does not change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.org_id, NEW.rotation_id, NEW.from_version, NEW.to_version, NEW.reason, NEW.started_by, NEW.started_at)
       IS DISTINCT FROM (OLD.org_id, OLD.rotation_id, OLD.from_version, OLD.to_version, OLD.reason, OLD.started_by,
                         OLD.started_at)
       OR NEW.rewrapped < OLD.rewrapped OR NEW.batches < OLD.batches THEN
        RAISE EXCEPTION 'consentvault.key_rotation: only the progress and state of a rotation change, forward'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER key_rotation_guard BEFORE UPDATE OR DELETE ON consentvault.key_rotation
    FOR EACH ROW EXECUTE FUNCTION consentvault.key_rotation_guard();
CREATE TRIGGER key_rotation_no_truncate BEFORE TRUNCATE ON consentvault.key_rotation
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

ALTER TABLE consentvault.key_rotation ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.key_rotation FORCE ROW LEVEL SECURITY;
CREATE POLICY key_rotation_tenant ON consentvault.key_rotation USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
REVOKE ALL ON consentvault.key_rotation FROM PUBLIC;


-- 4. The guards: a wrapped value changes only by a re-wrap -----------------------------------------------------------------
-- A re-wrap runs inside an owner function, which marks the transaction (consentvault.rewrap) for the length of its one
-- statement; the guard also requires the statement to run as the table's owner. Every other change is refused as before.
CREATE FUNCTION consentvault.rewrap_allowed(p_table oid) RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(current_setting('consentvault.rewrap', true), '') = 'on'
       AND current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = p_table);
$$;
REVOKE ALL ON FUNCTION consentvault.rewrap_allowed(oid) FROM PUBLIC;

CREATE FUNCTION consentvault.contact_key_rewrap_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT consentvault.rewrap_allowed(TG_RELID)
       OR (NEW.org_id, NEW.contact_fp, NEW.salt_ct, NEW.created_at)
          IS DISTINCT FROM (OLD.org_id, OLD.contact_fp, OLD.salt_ct, OLD.created_at)
       OR NEW.key_version <= OLD.key_version THEN
        RAISE EXCEPTION 'consentvault.contact_key: a contact key changes only by a re-wrap under a newer key version (UPDATE refused)'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- Replaced in place (the trigger guard refuses a drop): the trigger keeps its name and now runs the re-wrap guard.
CREATE OR REPLACE TRIGGER contact_key_no_update BEFORE UPDATE ON consentvault.contact_key
    FOR EACH ROW EXECUTE FUNCTION consentvault.contact_key_rewrap_guard();

-- A contact key is never written under a destroyed version. The FOR SHARE read waits on a transaction destroying that
-- version, then sees its outcome.
CREATE FUNCTION consentvault.contact_key_version_guard() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    st text;
BEGIN
    SELECT k.status INTO st FROM consentvault.org_key k
     WHERE k.org_id = NEW.org_id AND k.version = NEW.key_version FOR SHARE;
    IF st = 'destroyed' THEN
        RAISE EXCEPTION 'consentvault.contact_key: key version % of this organization is destroyed; wrap under the active version',
            NEW.key_version USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER contact_key_version_guard BEFORE INSERT OR UPDATE ON consentvault.contact_key
    FOR EACH ROW EXECUTE FUNCTION consentvault.contact_key_version_guard();

CREATE FUNCTION consentvault.org_fingerprint_secret_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' OR NOT consentvault.rewrap_allowed(TG_RELID)
       OR (NEW.org_id, NEW.created_at) IS DISTINCT FROM (OLD.org_id, OLD.created_at)
       OR consentvault.wrap_version(NEW.wrapped) <= consentvault.wrap_version(OLD.wrapped) THEN
        RAISE EXCEPTION 'consentvault.org_fingerprint_secret is append-only: % refused (only a re-wrap under a newer key version changes it)',
            TG_OP USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE TRIGGER org_fingerprint_secret_append_only BEFORE UPDATE OR DELETE ON consentvault.org_fingerprint_secret
    FOR EACH ROW EXECUTE FUNCTION consentvault.org_fingerprint_secret_guard();

-- The hold guard of 0014, with one more permitted change: a re-wrap of the sealed reasons, nothing else in the row.
CREATE OR REPLACE FUNCTION consentvault.legal_hold_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.legal_hold is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF consentvault.rewrap_allowed(TG_RELID)
       AND (NEW.org_id, NEW.hold_id, NEW.scope, NEW.contact_fps, NEW.set_by_kind, NEW.set_by, NEW.set_at,
            NEW.legal_process_id, NEW.set_ledger_seq, NEW.released_by_kind, NEW.released_by, NEW.released_at,
            NEW.release_ledger_seq)
           IS NOT DISTINCT FROM (OLD.org_id, OLD.hold_id, OLD.scope, OLD.contact_fps, OLD.set_by_kind, OLD.set_by,
                                 OLD.set_at, OLD.legal_process_id, OLD.set_ledger_seq, OLD.released_by_kind,
                                 OLD.released_by, OLD.released_at, OLD.release_ledger_seq)
       AND left(NEW.reason, 5) OPERATOR(pg_catalog.=) 'ocv1:'
       AND (NEW.release_reason IS NULL) OPERATOR(pg_catalog.=) (OLD.release_reason IS NULL) THEN
        RETURN NEW;
    END IF;
    IF OLD.released_at IS NOT NULL THEN
        RAISE EXCEPTION 'consentvault.legal_hold: a released hold does not change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.org_id, NEW.hold_id, NEW.scope, NEW.contact_fps, NEW.set_by_kind, NEW.set_by, NEW.set_at, NEW.reason,
        NEW.legal_process_id, NEW.set_ledger_seq)
       IS DISTINCT FROM (OLD.org_id, OLD.hold_id, OLD.scope, OLD.contact_fps, OLD.set_by_kind, OLD.set_by, OLD.set_at,
                         OLD.reason, OLD.legal_process_id, OLD.set_ledger_seq) THEN
        RAISE EXCEPTION 'consentvault.legal_hold: only the release columns change, once' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- A retired version is marked destroyed only when nothing is wrapped under it, inside its own organisation.
CREATE FUNCTION consentvault.org_key_version_guard() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    left_over text;
BEGIN
    IF OLD.status = 'retired' AND NEW.status = 'destroyed' THEN
        IF consentvault.current_org() IS DISTINCT FROM NEW.org_id THEN
            RAISE EXCEPTION 'consentvault.org_key: a key version is destroyed only inside its own organization'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        SELECT string_agg(c.kind || '=' || c.n, ', ') INTO left_over
          FROM consentvault.key_version_census_of(NEW.org_id, NEW.version) c WHERE c.n > 0;
        IF left_over IS NOT NULL THEN
            RAISE EXCEPTION 'key_version_in_use: version % still wraps %', NEW.version, left_over
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    IF OLD.status = 'destroyed' AND NEW.status IS DISTINCT FROM 'destroyed' THEN
        RAISE EXCEPTION 'consentvault.org_key: a destroyed key version stays destroyed' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER org_key_version_guard BEFORE UPDATE ON consentvault.org_key
    FOR EACH ROW EXECUTE FUNCTION consentvault.org_key_version_guard();

-- 5. The re-wraps, each a compare-and-swap inside the entered organisation ------------------------------------------------
CREATE FUNCTION consentvault.rewrap_target_ok(p_org uuid, p_to_version integer) RETURNS void
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_org IS NULL THEN
        RAISE EXCEPTION 'consentvault re-wrap refused: no organization is entered' USING ERRCODE = 'insufficient_privilege';
    END IF;
    PERFORM 1 FROM consentvault.org_key k
     WHERE k.org_id = p_org AND k.version = p_to_version AND k.status = 'active'
       AND NOT EXISTS (SELECT 1 FROM consentvault.org_key n WHERE n.org_id = p_org AND n.version > p_to_version);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault re-wrap refused: version % is not the active key version of this organization', p_to_version
            USING ERRCODE = 'raise_exception';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.rewrap_target_ok(uuid, integer) FROM PUBLIC;

CREATE FUNCTION consentvault.rewrap_contact_key(p_contact_fp text, p_from_version integer, p_wrapped bytea,
                                                p_to_version integer) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.current_org();
    n   integer;
BEGIN
    PERFORM consentvault.rewrap_target_ok(org, p_to_version);
    IF p_from_version >= p_to_version OR p_wrapped IS NULL OR octet_length(p_wrapped) < 16 THEN
        RAISE EXCEPTION 'consentvault re-wrap refused: a contact key moves to a newer version with a wrapped key'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM set_config('consentvault.rewrap', 'on', true);
    UPDATE consentvault.contact_key SET wrapped_key = p_wrapped, key_version = p_to_version
     WHERE org_id = org AND contact_fp = p_contact_fp AND key_version = p_from_version;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('consentvault.rewrap', 'off', true);
    RETURN n = 1;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.rewrap_contact_key(text, integer, bytea, integer) FROM PUBLIC;

-- p_kind: 'fingerprint_secret' (p_ref ignored), 'credential' or 'connected_system' (p_ref the row's id).
CREATE FUNCTION consentvault.rewrap_org_secret(p_kind text, p_ref uuid, p_old bytea, p_new bytea) RETURNS boolean
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
REVOKE ALL ON FUNCTION consentvault.rewrap_org_secret(text, uuid, bytea, bytea) FROM PUBLIC;

CREATE FUNCTION consentvault.rewrap_hold_reason(p_hold uuid, p_old_reason text, p_new_reason text,
                                                p_old_release text, p_new_release text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.current_org();
    n   integer;
BEGIN
    PERFORM consentvault.rewrap_target_ok(org, consentvault.sealed_version(p_new_reason));
    IF (p_new_release IS NOT NULL
        AND consentvault.sealed_version(p_new_release) IS DISTINCT FROM consentvault.sealed_version(p_new_reason)) THEN
        RAISE EXCEPTION 'consentvault re-wrap refused: both reasons of a hold move to the same version'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM set_config('consentvault.rewrap', 'on', true);
    UPDATE consentvault.legal_hold SET reason = p_new_reason, release_reason = p_new_release
     WHERE org_id = org AND hold_id = p_hold AND reason = p_old_reason
       AND release_reason IS NOT DISTINCT FROM p_old_release;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('consentvault.rewrap', 'off', true);
    RETURN n = 1;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.rewrap_hold_reason(uuid, text, text, text, text) FROM PUBLIC;

-- 6. What the operator console and its jobs may do -------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE (status, blocked_reason, rewrapped, batches, last_batch_at, completed_at)
    ON consentvault.key_rotation TO consentvault_console;
GRANT INSERT (org_id, name, ref_kind, ref_id, error_class, request_id) ON consentvault.operator_alarm
    TO consentvault_console;
GRANT EXECUTE ON FUNCTION consentvault.key_version_census(integer),
    consentvault.rewrap_contact_key(text, integer, bytea, integer),
    consentvault.rewrap_org_secret(text, uuid, bytea, bytea),
    consentvault.rewrap_hold_reason(uuid, text, text, text, text)
    TO consentvault_console;
