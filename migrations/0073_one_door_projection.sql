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

-- Whether the entered organisation's projection already counted a request, for any scope of the tenant (a boolean, no personal
-- data): the projection asks it before it spends an evidence object on a copy of a request it has already counted.
CREATE FUNCTION consentvault.request_counted(p_key text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM consentvault.event_source_post s
                    WHERE s.org_id OPERATOR(pg_catalog.=) consentvault.current_org()
                      AND s.role OPERATOR(pg_catalog.=) 'trigger' AND s.request_key OPERATOR(pg_catalog.=) p_key);
$$;
REVOKE ALL ON FUNCTION consentvault.request_counted(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.request_counted(text) TO consentvault_app;
