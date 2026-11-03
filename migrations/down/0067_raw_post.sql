-- Reverses 0067_raw_post.sql. Refuses while any raw post exists: a down migration never destroys evidence.
-- Run it as a superuser (or a BYPASSRLS role), in one transaction, like the 0008 down.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regclass('consentvault.raw_post') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0067 refused: consentvault.raw_post is missing; 0067 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.raw_post)
       OR EXISTS (SELECT 1 FROM consentvault.form_field_map)
       OR EXISTS (SELECT 1 FROM consentvault.raw_post_chain_head) THEN
        RAISE EXCEPTION 'consentvault down 0067 refused: the vault holds raw posts, form field maps or raw-post anchors';
    END IF;
END
$$;

DROP TABLE consentvault.seen_payload;
DROP TABLE consentvault.event_source_post;
DROP TABLE consentvault.raw_post_seal;
DROP FUNCTION consentvault.raw_post_seal_guard();
DROP FUNCTION consentvault.mark_raw_post_seal_verified(uuid);
DROP TABLE consentvault.raw_post_match;
DROP TABLE consentvault.raw_post_field;
DROP TABLE consentvault.form_field_map;
DROP TABLE consentvault.raw_post_fact;
DROP TABLE consentvault.raw_post_chain_head;
DROP TABLE consentvault.raw_post_key;
DROP FUNCTION consentvault.raw_post_key_delete_guard();
DROP FUNCTION consentvault.erase_raw_post_key(uuid);
DROP FUNCTION consentvault.raw_post_head();
DROP TABLE consentvault.raw_post;
DROP FUNCTION consentvault.check_raw_post_chain();
DROP FUNCTION consentvault.raw_post_lock_key(uuid);

COMMIT;
