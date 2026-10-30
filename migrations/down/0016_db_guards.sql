-- Reverses 0016_db_guards.sql: the app regains the release columns and full-row INSERT on the request tables (the 0014
-- grants). Run it as a superuser, in one transaction.
BEGIN;

DO $$
BEGIN
    IF to_regprocedure('consentvault.release_hold_as_member(uuid, text, timestamptz, bigint, text)') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0016 refused: 0016 is not applied';
    END IF;
END
$$;

DROP TRIGGER offboarding_request_initial ON consentvault.offboarding_request;
DROP FUNCTION consentvault.offboarding_request_initial();
DROP TRIGGER erasure_request_initial ON consentvault.erasure_request;
DROP FUNCTION consentvault.erasure_request_initial();
REVOKE INSERT (org_id, request_id, reason, requested_by) ON consentvault.offboarding_request FROM consentvault_app;
GRANT INSERT ON consentvault.offboarding_request TO consentvault_app;
REVOKE INSERT (org_id, erasure_id, contact_fp, reason, requested_by) ON consentvault.erasure_request FROM consentvault_app;
GRANT INSERT ON consentvault.erasure_request TO consentvault_app;

DROP FUNCTION consentvault.release_hold_as_operator(uuid, text, timestamptz, bigint, text);
DROP FUNCTION consentvault.release_hold_as_member(uuid, text, timestamptz, bigint, text);
DROP FUNCTION consentvault.release_hold_row(uuid, uuid, text, text, text, timestamptz, bigint);
GRANT UPDATE (released_by_kind, released_by, released_at, release_reason, release_ledger_seq)
    ON consentvault.legal_hold TO consentvault_app;

COMMIT;
