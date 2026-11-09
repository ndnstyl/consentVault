-- Reverses 0099_confirmation_enqueue_retired_at_cutover.sql: the original function has its name and its grant again.
BEGIN;
DROP FUNCTION consentvault.confirmation_enqueue(uuid, text);
ALTER FUNCTION consentvault.confirmation_enqueue_before_cutover(uuid, text) RENAME TO confirmation_enqueue;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_enqueue(uuid, text) TO consentvault_app;
COMMIT;
