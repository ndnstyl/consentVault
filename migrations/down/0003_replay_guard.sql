-- Reverses 0003_replay_guard.sql. The guard holds only short-lived nonces, never evidence.
DROP FUNCTION consentvault.sweep_replay_guard();
DROP FUNCTION consentvault.claim_replay_nonce(uuid, text, timestamptz);
DROP TABLE consentvault.replay_guard;
