-- Reverses 0082_fact_status_order_and_chain.sql: the chain trigger, its function and the six columns are dropped. Facts written
-- before and after keep their ciphertext, source and name; only the status, label, order and chain are lost.
BEGIN;
DROP TRIGGER raw_post_fact_chain ON consentvault.raw_post_fact;
DROP FUNCTION consentvault.raw_post_fact_chain();
DROP FUNCTION consentvault.fact_digest(uuid, uuid, bigint, text, text, bytea, text, text, text, text);
DROP INDEX consentvault.raw_post_fact_seq_key;
DROP INDEX consentvault.raw_post_fact_prev_key;
ALTER TABLE consentvault.raw_post_fact
    DROP COLUMN status, DROP COLUMN label, DROP COLUMN fact_seq, DROP COLUMN observed_at, DROP COLUMN fact_sha256,
    DROP COLUMN prev_fact_sha256;
COMMIT;
