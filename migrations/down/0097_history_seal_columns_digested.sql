-- Reverses 0097_history_seal_columns_digested.sql.
BEGIN;
ALTER TABLE consentvault.post_history_seal RENAME COLUMN columns_digested TO columns;
ALTER TABLE consentvault.post_history_chain_head RENAME COLUMN history_seq TO seq;
COMMIT;
