-- Reverses 0110_disclosure_replaces_guard_search_path.sql: the guard returns to its 0092 definition with no pinned search path.
BEGIN;
ALTER FUNCTION consentvault.disclosure_replaces_guard() RESET search_path;
COMMIT;
