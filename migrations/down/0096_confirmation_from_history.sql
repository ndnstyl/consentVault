-- Reverses 0096_confirmation_from_history.sql. Send rows made from history stay; they simply stop mirroring into effect_intent.
BEGIN;
DROP TRIGGER confirmation_send_state_to_intent ON consentvault.confirmation_send_intent;
DROP FUNCTION consentvault.confirmation_send_state_to_intent();
DROP FUNCTION consentvault.confirmation_send_from_history(uuid, uuid, uuid, uuid, text, text);
COMMIT;
