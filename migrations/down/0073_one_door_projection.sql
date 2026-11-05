-- Reverses 0073_one_door_projection.sql. Refuses while a link row carries a request key: dropping the column would lose the
-- identity of every request the projection already counted.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'consentvault'
                   AND table_name = 'event_source_post' AND column_name = 'request_key') THEN
        RAISE EXCEPTION 'consentvault down 0073 refused: 0073 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.event_source_post WHERE request_key IS NOT NULL) THEN
        RAISE EXCEPTION 'consentvault down 0073 refused: the projection holds request keys';
    END IF;
END
$$;

GRANT INSERT (org_id, request_key, post_id) ON consentvault.seen_request TO consentvault_app;
DROP INDEX consentvault.event_source_post_one_request;
DROP INDEX consentvault.event_source_post_one_trigger;
REVOKE INSERT (request_key) ON consentvault.event_source_post FROM consentvault_app;
ALTER TABLE consentvault.event_source_post DROP COLUMN request_key;

COMMIT;
