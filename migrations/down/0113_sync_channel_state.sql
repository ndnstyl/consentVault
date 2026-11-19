-- Undo 0113: the channel-state reader goes. Nothing is stored by it.
BEGIN;
DROP FUNCTION IF EXISTS consentvault.sync_channel_state(text, text);
COMMIT;
