-- Reverses 0074_restore_reingests_as_a_post.sql: the operator console's role loses the appends on the post store. A restore then
-- cannot re-ingest a stop as a post; nothing stored is touched.
BEGIN;
REVOKE EXECUTE ON FUNCTION consentvault.request_counted(text) FROM consentvault_console;
REVOKE EXECUTE ON FUNCTION consentvault.raw_post_lock_key(uuid) FROM consentvault_console;
REVOKE INSERT (org_id, event_id, post_id, role, request_key) ON consentvault.event_source_post FROM consentvault_console;
REVOKE INSERT (org_id, post_id, fact_id, source, name, value_ct, arrival_ordinal) ON consentvault.raw_post_fact FROM consentvault_console;
REVOKE INSERT (org_id, post_id, post_key_wrapped, key_version) ON consentvault.raw_post_key FROM consentvault_console;
REVOKE INSERT ON consentvault.raw_post, consentvault.raw_post_chain_head FROM consentvault_console;
COMMIT;
