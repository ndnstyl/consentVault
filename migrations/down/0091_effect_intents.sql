-- Reverses 0091_effect_intents.sql: the seed, the replay test, the intent id function, the intent guard and the two tables are dropped.
-- Run it before any intent has been sent: a sent intent is the only record that a vendor was called. Nothing the old fold uses is touched.
BEGIN;
DROP FUNCTION consentvault.seed_effect_intents();
DROP FUNCTION consentvault.is_replay_database();
DROP FUNCTION consentvault.effect_intent_id(uuid, text);
DROP FUNCTION consentvault.effect_intent_move(uuid, text);
DROP TABLE consentvault.effect_watermark;
DROP TABLE consentvault.effect_intent;
DROP FUNCTION consentvault.effect_intent_guard();
COMMIT;
