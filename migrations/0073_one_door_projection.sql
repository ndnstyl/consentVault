-- The events are a rebuildable projection of the stored posts. Each event cites the one post it came from, and the unique keys
-- below make a second projection of the same post (a re-run after a crash) or of the same signed request a refused insert, which
-- the projection reads as "already done". The request key rides on the link row of the post that produced the event, so the
-- fold decides a duplicate by looking at earlier posts, and nothing claims a request at intake any more.
--
-- seen_request is retired: no code reads or writes it and the runtime role can no longer insert into it. The table itself stays
-- (the database refuses to drop an append-only table's triggers, so removing it is a superuser's break-glass, not a migration);
-- any row it already holds is history.
ALTER TABLE consentvault.event_source_post ADD COLUMN request_key text;
CREATE UNIQUE INDEX event_source_post_one_trigger ON consentvault.event_source_post (org_id, post_id) WHERE role = 'trigger';
CREATE UNIQUE INDEX event_source_post_one_request ON consentvault.event_source_post (org_id, request_key)
    WHERE role = 'trigger' AND request_key IS NOT NULL;
GRANT INSERT (request_key) ON consentvault.event_source_post TO consentvault_app;
REVOKE INSERT ON consentvault.seen_request FROM consentvault_app;
