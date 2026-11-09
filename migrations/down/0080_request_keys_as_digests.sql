-- Reverses 0080_request_keys_as_digests.sql: the two tables' change guard is the plain refusal again. The rewritten keys stay as
-- they are: a digest cannot be turned back into the key it came from, and the code that reads these tables (0078 and later)
-- looks keys up by digest. The plaintext of every key is still held, encrypted, as the request_key fact beside its post.
BEGIN;
CREATE OR REPLACE TRIGGER event_source_post_append_only BEFORE UPDATE OR DELETE ON consentvault.event_source_post
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE OR REPLACE TRIGGER raw_post_request_append_only BEFORE UPDATE OR DELETE ON consentvault.raw_post_request
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
DROP FUNCTION consentvault.refuse_change_except_key_digest();
COMMIT;
