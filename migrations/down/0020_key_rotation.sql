-- Reverses 0020_key_rotation.sql. Run it as a superuser, in one transaction. Contact keys already re-wrapped stay
-- valid rows (key_version and its reference to org_key are 0002's); only the rotation machinery goes.
BEGIN;

DO $$
BEGIN
    IF to_regclass('consentvault.key_rotation') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0020 refused: 0020 is not applied';
    END IF;
END
$$;

REVOKE ALL ON consentvault.operator_alarm FROM consentvault_console;
DROP FUNCTION consentvault.rewrap_hold_reason(uuid, text, text, text, text);
DROP FUNCTION consentvault.rewrap_org_secret(text, uuid, bytea, bytea);
DROP FUNCTION consentvault.rewrap_contact_key(text, integer, bytea, integer);
DROP FUNCTION consentvault.rewrap_target_ok(uuid, integer);

DROP TRIGGER org_key_version_guard ON consentvault.org_key;
DROP FUNCTION consentvault.org_key_version_guard();

-- The hold guard goes back to its 0014 shape.
CREATE OR REPLACE FUNCTION consentvault.legal_hold_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.legal_hold is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
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

CREATE OR REPLACE TRIGGER org_fingerprint_secret_append_only BEFORE UPDATE OR DELETE ON consentvault.org_fingerprint_secret
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
DROP FUNCTION consentvault.org_fingerprint_secret_guard();

DROP TRIGGER contact_key_version_guard ON consentvault.contact_key;
DROP FUNCTION consentvault.contact_key_version_guard();
CREATE OR REPLACE TRIGGER contact_key_no_update BEFORE UPDATE ON consentvault.contact_key
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
DROP FUNCTION consentvault.contact_key_rewrap_guard();
DROP FUNCTION consentvault.rewrap_allowed(oid);

DROP TABLE consentvault.key_rotation;
DROP FUNCTION consentvault.key_rotation_guard();
DROP FUNCTION consentvault.key_version_census(integer);
DROP FUNCTION consentvault.key_version_census_of(uuid, integer);
DROP FUNCTION consentvault.sealed_version(text);
DROP FUNCTION consentvault.wrap_version(bytea);

COMMIT;
