-- Reverses 0018_gag_safety.sql. Run it as a superuser (or a BYPASSRLS role), in one transaction.
-- Refuses while an emergency operator access with no customer notice is recorded (it exists only under a gag, and the
-- 0017 shape cannot hold it), or while an erasure request is queued behind an operator's hold (0017 refuses such a
-- request at insert).
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regprocedure('consentvault.hold_disclosure(uuid)') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0018 refused: 0018 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.operator_access WHERE emergency AND client_notified_at IS NULL) THEN
        RAISE EXCEPTION 'consentvault down 0018 refused: an emergency access under a gag is recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.erasure_request r JOIN consentvault.legal_hold h
                 ON h.org_id = r.org_id AND h.hold_id = r.held_by
                WHERE r.status = 'pending_operator_confirmation' AND h.set_by_kind = 'operator' AND r.confirmed_by IS NULL)
    THEN
        RAISE EXCEPTION 'consentvault down 0018 refused: an unconfirmed erasure request is queued behind an operator hold';
    END IF;
END
$$;

DROP TRIGGER operator_access_gag ON consentvault.operator_access;
DROP FUNCTION consentvault.operator_access_gag();
ALTER TABLE consentvault.operator_access DROP CONSTRAINT operator_access_basis;
ALTER TABLE consentvault.operator_access ADD CONSTRAINT operator_access_basis CHECK (
    (approved_by_client IS NOT NULL AND NOT emergency)
    OR (approved_by_client IS NULL AND emergency AND client_notified_at IS NOT NULL));

CREATE OR REPLACE FUNCTION consentvault.erasure_request_guard() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    h uuid;
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.erasure_request is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF TG_OP OPERATOR(pg_catalog.=) 'INSERT' THEN
        h := consentvault.legal_hold_on(NEW.org_id, NEW.contact_fp);
        IF h IS NOT NULL THEN
            RAISE EXCEPTION 'legal_hold_active:%', h USING ERRCODE = 'integrity_constraint_violation',
                DETAIL = 'a legal hold covers this contact; the erasure request is refused';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.org_id, NEW.erasure_id, NEW.contact_fp, NEW.reason, NEW.requested_by, NEW.requested_at)
       IS DISTINCT FROM (OLD.org_id, OLD.erasure_id, OLD.contact_fp, OLD.reason, OLD.requested_by, OLD.requested_at)
       OR OLD.status <> 'pending_operator_confirmation' THEN
        RAISE EXCEPTION 'consentvault.erasure_request: only an open request changes, and only its status columns'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP FUNCTION consentvault.erasure_hold(uuid);
REVOKE SELECT ON consentvault.erasure_request FROM consentvault_app;
GRANT SELECT ON consentvault.erasure_request TO consentvault_app;
REVOKE SELECT ON consentvault.destruction_record FROM consentvault_app;
GRANT SELECT ON consentvault.destruction_record TO consentvault_app;
REVOKE SELECT ON consentvault.legal_hold FROM consentvault_app;
GRANT SELECT ON consentvault.legal_hold TO consentvault_app;
DROP POLICY legal_hold_tenant_disclosed ON consentvault.legal_hold;

DROP FUNCTION consentvault.hold_disclosure(uuid);
DROP FUNCTION consentvault.legal_process_disclosed(uuid, uuid);

COMMIT;
