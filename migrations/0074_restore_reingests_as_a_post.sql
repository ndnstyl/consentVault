-- A restore re-ingests a stop it found in the evidence store by storing it as a post of its own and projecting it through the
-- one door (so the event cites its post and a rebuild can reproduce it). The operator console's role therefore needs the same
-- appends the runtime role has on the post store and the link to it, and nothing more: no update, no delete, no read widening.
GRANT INSERT ON consentvault.raw_post, consentvault.raw_post_chain_head TO consentvault_console;
GRANT INSERT (org_id, post_id, post_key_wrapped, key_version) ON consentvault.raw_post_key TO consentvault_console;
GRANT INSERT (org_id, post_id, fact_id, source, name, value_ct, arrival_ordinal) ON consentvault.raw_post_fact TO consentvault_console;
GRANT INSERT (org_id, event_id, post_id, role, request_key) ON consentvault.event_source_post TO consentvault_console;
GRANT EXECUTE ON FUNCTION consentvault.raw_post_lock_key(uuid) TO consentvault_console;
GRANT EXECUTE ON FUNCTION consentvault.request_counted(text) TO consentvault_console;
