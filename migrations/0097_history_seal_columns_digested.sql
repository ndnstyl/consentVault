-- Pure projection, item 29: the history seal names the list of columns its digest covers as ``columns_digested`` (the name the check reads);
-- the column list a seal recorded is unchanged, only the name moves, so no seal is touched.
ALTER TABLE consentvault.post_history_seal RENAME COLUMN columns TO columns_digested;
-- and the anchor of the history chain names its sequence number as history_seq, the name the rows of the chain itself carry.
ALTER TABLE consentvault.post_history_chain_head RENAME COLUMN seq TO history_seq;
