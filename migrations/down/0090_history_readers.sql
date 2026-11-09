-- Reverses 0090_history_readers.sql: the history-reading functions and the fold's three reads are dropped. Nothing the old fold calls was touched by the
-- migration, so nothing is restored.
BEGIN;
DROP FUNCTION consentvault.fold_earliest_copy(uuid, text);
DROP FUNCTION consentvault.fold_fact_rows(uuid);
DROP FUNCTION consentvault.fold_post_place(uuid);
DROP FUNCTION consentvault.history_stop_on_record(uuid, text, text);
DROP FUNCTION consentvault.unsealed_history();
DROP FUNCTION consentvault.history_chain_breaks();
DROP FUNCTION consentvault.history_head();
COMMIT;
