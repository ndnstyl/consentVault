-- Reverses 0013_dispatch_per_org.sql. Run it as a superuser (or a BYPASSRLS role), in one transaction.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regprocedure('consentvault.dispatch_org_token(text, uuid)') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0013 refused: 0013 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.delivery WHERE error_class = 'prepare_failed') THEN
        RAISE EXCEPTION 'consentvault down 0013 refused: deliveries record prepare_failed attempts';
    END IF;
END
$$;

ALTER TABLE consentvault.outbox DROP CONSTRAINT outbox_last_error_class_check;
ALTER TABLE consentvault.outbox ADD CONSTRAINT outbox_last_error_class_check
    CHECK (last_error_class IN ('timeout', 'http_4xx', 'http_5xx', 'signature_rejected', 'unreachable'));
ALTER TABLE consentvault.delivery DROP CONSTRAINT delivery_error_class_check;
ALTER TABLE consentvault.delivery ADD CONSTRAINT delivery_error_class_check
    CHECK (error_class IN ('timeout', 'http_4xx', 'http_5xx', 'signature_rejected', 'unreachable'));
DROP FUNCTION consentvault.dispatch_org_token(text, uuid);
DROP FUNCTION consentvault.dispatch_org_ids(text);

COMMIT;
