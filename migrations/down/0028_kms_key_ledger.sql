-- Reverses 0028_kms_key_ledger.sql. Run it as the schema owner, in one transaction. The ledger's rows go with it.
BEGIN;

DO $$
BEGIN
    IF to_regclass('consentvault.kms_key_ledger') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0028 refused: 0028 is not applied';
    END IF;
END
$$;

DROP FUNCTION consentvault.kms_key_ledger_write(text, jsonb);
DROP FUNCTION consentvault.kms_key_ledger_read();
DROP TABLE consentvault.kms_key_ledger;

COMMIT;
