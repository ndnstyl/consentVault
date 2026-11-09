-- Reverses 0084_post_history.sql: the history table, its chain trigger and function are dropped. The posts and their facts, which the
-- history was derived from, are untouched; the history is derived again by projecting them.
BEGIN;
DROP TABLE consentvault.post_history;
DROP FUNCTION consentvault.post_history_chain();
COMMIT;
