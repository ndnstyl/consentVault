-- Reverses 0070_single_fingerprint_secret.sql. Refuses while the secret exists: removing it would orphan every fingerprint made with it.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regclass('consentvault.single_fingerprint_secret') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0070 refused: 0070 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.single_fingerprint_secret) THEN
        RAISE EXCEPTION 'consentvault down 0070 refused: the vault holds its fingerprint secret';
    END IF;
END
$$;

DROP FUNCTION consentvault.single_fingerprint_secret(bytea);
DROP TABLE consentvault.single_fingerprint_secret;

COMMIT;
