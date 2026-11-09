-- Reverses 0087_history_seal_and_anchor.sql: the history seals and anchors are dropped with their guard functions. The history itself
-- is untouched; its rows are sealed and anchored again by the seal job.
BEGIN;
DROP TABLE consentvault.post_history_chain_head;
DROP TABLE consentvault.post_history_seal;
DROP FUNCTION consentvault.mark_post_history_seal_verified(uuid);
DROP FUNCTION consentvault.post_history_seal_guard();
COMMIT;
