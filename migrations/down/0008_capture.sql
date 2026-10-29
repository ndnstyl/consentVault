-- Reverses 0008_capture.sql. Refuses while any gate decision, evidence object, EBR record or DNC scrub result exists:
-- a down migration never destroys evidence.
-- Run it as a superuser (or a BYPASSRLS role), in one transaction, like the tenancy down.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regclass('consentvault.gate_decision') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0008 refused: consentvault.gate_decision is missing; 0008 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.gate_decision)
       OR EXISTS (SELECT 1 FROM consentvault.evidence_object)
       OR EXISTS (SELECT 1 FROM consentvault.ebr_record)
       OR EXISTS (SELECT 1 FROM consentvault.dnc_scrub_result)
       THEN
        RAISE EXCEPTION 'consentvault down 0008 refused: the vault holds gate decisions, evidence objects or client-supplied evidence';
    END IF;
END
$$;

DROP TABLE consentvault.dnc_scrub_result;
DROP TABLE consentvault.ebr_record;
DROP FUNCTION consentvault.ensure_gate_decision_partitions(integer);
DROP TABLE consentvault.gate_decision;
DROP TABLE consentvault.evidence_object;
DROP FUNCTION consentvault.evidence_object_guard();
DROP FUNCTION consentvault.receipt_of(uuid);

CREATE OR REPLACE FUNCTION consentvault.require_multi_tenant() RETURNS void
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (SELECT mode FROM consentvault.tenancy_setting WHERE singleton) IS DISTINCT FROM 'multi' THEN
        RAISE EXCEPTION 'consentvault tenancy: this vault is in single mode; a multi-tenant service must not serve it'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
END;
$$;
DROP FUNCTION consentvault.owner_rights_violations();

COMMIT;
