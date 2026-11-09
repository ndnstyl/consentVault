-- Reverses 0092_wording_replaces_guard.sql: the insert-time check goes; stored links and wording are untouched.
BEGIN;
DROP TRIGGER disclosure_replaces_guard ON consentvault.disclosure;
DROP FUNCTION consentvault.disclosure_replaces_guard();
COMMIT;
