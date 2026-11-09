-- Reverses 0095_cutover_reads.sql.
BEGIN;
DROP FUNCTION consentvault.confirmation_rules_enabled();
COMMIT;
