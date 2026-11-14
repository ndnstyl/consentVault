-- Reverses 0046_record_export.sql. Run it as a superuser, in one transaction. Requested export rows are job records only;
-- the files they point at are kept by the export worker and are not touched here.
BEGIN;
DO $$
BEGIN
    IF to_regclass('consentvault.record_export') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0046 refused: 0046 is not applied';
    END IF;
    IF to_regclass('consentvault_guard.table_pin') IS NOT NULL THEN
        DELETE FROM consentvault_guard.table_pin WHERE rel = 'consentvault.record_export'::regclass;
    END IF;
END
$$;
DROP TABLE consentvault.record_export_link;
DROP TABLE consentvault.record_export;
DROP FUNCTION consentvault.may_read_record_exports();
COMMIT;
