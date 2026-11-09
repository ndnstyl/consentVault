-- Reverses 0088_retrieval_log.sql: the retrieval log and its chain trigger are dropped. The history and the posts are untouched.
BEGIN;
DROP TABLE consentvault.retrieval_log;
DROP FUNCTION consentvault.retrieval_log_chain();
COMMIT;
