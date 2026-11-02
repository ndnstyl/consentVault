-- Reverses 0043_erasure_covers_seq.sql. Run it as a superuser (the trigger guard refuses changes to pinned guards for anyone
-- else), in one transaction. The pins of the objects dropped here are cleared; a superuser re-pins after the next migration run.
BEGIN;
DO $$
BEGIN
    IF to_regclass('consentvault_guard.pin') IS NOT NULL THEN
        DELETE FROM consentvault_guard.pin WHERE identity IN ('consentvault.erasure_request_cover()',
            'erasure_request_cover on consentvault.erasure_request', 'erasure_coverage_no_change on consentvault.erasure_coverage',
            'erasure_coverage_no_truncate on consentvault.erasure_coverage');
    END IF;
    IF to_regclass('consentvault_guard.table_pin') IS NOT NULL THEN
        DELETE FROM consentvault_guard.table_pin WHERE rel = 'consentvault.erasure_coverage'::regclass;
    END IF;
END
$$;
DROP TRIGGER erasure_request_cover ON consentvault.erasure_request;
DROP FUNCTION consentvault.erasure_request_cover();
DROP TABLE consentvault.erasure_coverage;
COMMIT;
