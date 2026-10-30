-- Reverses 0014_erasure_holds.sql. Run it as a superuser (or a BYPASSRLS role), in one transaction.
-- Refuses while any legal hold, destruction record, erasure request (pending, declined or completed), taken or delivered
-- final export, restore record, legal process or operator access exists: each is evidence of what was asked, preserved,
-- delivered or destroyed.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regclass('consentvault.legal_hold') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0014 refused: 0014 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.legal_hold) THEN
        RAISE EXCEPTION 'consentvault down 0014 refused: legal holds are recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.destruction_record) THEN
        RAISE EXCEPTION 'consentvault down 0014 refused: destruction records exist';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.erasure_request WHERE status = 'completed') THEN
        RAISE EXCEPTION 'consentvault down 0014 refused: completed erasures are recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.erasure_request
                WHERE status IN ('pending_operator_confirmation', 'declined')) THEN
        RAISE EXCEPTION 'consentvault down 0014 refused: pending or declined erasures are recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.offboarding_request
                WHERE final_export_at IS NOT NULL OR steps ? 'final_export_delivered') THEN
        RAISE EXCEPTION 'consentvault down 0014 refused: an offboarding records a taken or delivered final export';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.restore_run) THEN
        RAISE EXCEPTION 'consentvault down 0014 refused: a restore is recorded';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.legal_process) OR EXISTS (SELECT 1 FROM consentvault.operator_access) THEN
        RAISE EXCEPTION 'consentvault down 0014 refused: legal process or operator access is recorded';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION consentvault.evidence_org_ids() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT org_id FROM consentvault.organization WHERE status <> 'closed' ORDER BY org_id;
$$;
DROP FUNCTION consentvault.restore_org_ids();

DROP TRIGGER gate_decision_restore_guard ON consentvault.gate_decision;
DROP FUNCTION consentvault.gate_decision_restore_guard();
DROP FUNCTION consentvault.restore_pending();
DROP TABLE consentvault.restore_run;

DROP TRIGGER org_key_hold_guard ON consentvault.org_key;
DROP FUNCTION consentvault.org_key_hold_guard();
DROP TRIGGER contact_key_hold_guard ON consentvault.contact_key;
DROP FUNCTION consentvault.contact_key_hold_guard();
DROP FUNCTION consentvault.erase_contact(text);

DROP TABLE consentvault.operator_access;
DROP FUNCTION consentvault.operator_access_guard();
DROP TABLE consentvault.legal_process;
DROP FUNCTION consentvault.legal_process_guard();
DROP TABLE consentvault.destruction_record;
DROP TABLE consentvault.offboarding_request;
DROP FUNCTION consentvault.offboarding_request_guard();
DROP TABLE consentvault.erasure_request;
DROP FUNCTION consentvault.erasure_request_guard();
DROP FUNCTION consentvault.legal_hold_on(uuid, text);
DROP FUNCTION consentvault.legal_hold_covering(text);
DROP FUNCTION consentvault.lifecycle_lock();
DROP TABLE consentvault.legal_hold;
DROP FUNCTION consentvault.legal_hold_guard();
DROP FUNCTION consentvault.all_fingerprints(text[]);

COMMIT;
