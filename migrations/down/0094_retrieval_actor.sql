-- Reverses 0094_retrieval_actor.sql: the function that names the caller of a retrieval is dropped. Logged rows stay.
BEGIN;
DROP FUNCTION consentvault.current_token_credential();
COMMIT;
