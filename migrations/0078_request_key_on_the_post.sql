-- The request key is a stored, indexed column of its own beside every post that carries one (specs/capture-everything/one-door.md,
-- addendum point 4). A request key is the request's own identity: the id the edge minted for it, else a request id header joined
-- to the hash of the body, else the signature it was signed with, else the provider's message id.
--
-- Until now the key was an encrypted fact beside the post and a column of the event link, so which of two copies of one request
-- counted depended on which copy the projection reached first. An event is now placed in a person's history by the EARLIEST post
-- that carries its key, whichever copy produced the event. A replay from empty gives the same history whichever copy projected
-- first, because the place is read from the posts alone.
--
-- raw_post is append-only and hash-chained, and a key learned after the post (a provider reply is authenticated after it is stored)
-- or backfilled for a post stored before this migration cannot be written into it, so the key is a column of a table of its own:
-- one row per post, append-only, written by the post writer in the same transaction as the post, or by the backfill the projection
-- runs (door.backfill_request_keys reads the key from the post's stored facts, which the database alone cannot open).
CREATE TABLE consentvault.raw_post_request (
    org_id      uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    post_id     uuid NOT NULL,
    request_key text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, post_id),
    FOREIGN KEY (org_id, post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE INDEX raw_post_request_key_idx ON consentvault.raw_post_request (org_id, request_key);
CREATE TRIGGER raw_post_request_append_only BEFORE UPDATE OR DELETE ON consentvault.raw_post_request
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER raw_post_request_no_truncate BEFORE TRUNCATE ON consentvault.raw_post_request
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

ALTER TABLE consentvault.raw_post_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.raw_post_request FORCE ROW LEVEL SECURITY;
CREATE POLICY raw_post_request_tenant ON consentvault.raw_post_request USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
CREATE POLICY raw_post_request_read_scope ON consentvault.raw_post_request AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_evidence()));

GRANT SELECT ON consentvault.raw_post_request TO consentvault_app, consentvault_console;
GRANT INSERT (org_id, post_id, request_key) ON consentvault.raw_post_request TO consentvault_app;

-- Where an event sits in the arrival order: the earliest post (by its place in the arrival chain) among the post that triggered the
-- event and every post that carries the event's request key. Runs as the owner, so the answer does not depend on the reader's
-- evidence scope; reads only the entered organisation's rows and returns no personal data.
CREATE FUNCTION consentvault.arrival_place(p_org uuid, p_event_id uuid) RETURNS TABLE (received_at timestamptz, post_seq bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT rp.received_at, rp.seq
      FROM consentvault.raw_post rp
     WHERE rp.org_id OPERATOR(pg_catalog.=) p_org
       AND rp.post_id OPERATOR(pg_catalog.=) ANY (
           SELECT s.post_id FROM consentvault.event_source_post s
            WHERE s.org_id OPERATOR(pg_catalog.=) p_org AND s.event_id OPERATOR(pg_catalog.=) p_event_id
              AND s.role OPERATOR(pg_catalog.=) 'trigger'
           UNION
           SELECT q.post_id FROM consentvault.event_source_post s
             JOIN consentvault.raw_post_request q ON q.org_id OPERATOR(pg_catalog.=) s.org_id AND q.request_key OPERATOR(pg_catalog.=) s.request_key
            WHERE s.org_id OPERATOR(pg_catalog.=) p_org AND s.event_id OPERATOR(pg_catalog.=) p_event_id
              AND s.role OPERATOR(pg_catalog.=) 'trigger' AND s.request_key IS NOT NULL)
     ORDER BY rp.seq
     LIMIT 1;
$$;
REVOKE ALL ON FUNCTION consentvault.arrival_place(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.arrival_place(uuid, uuid) TO consentvault_app, consentvault_worker, consentvault_console,
    consentvault_isolation_self_test;

CREATE FUNCTION consentvault.arrival_post_seq(p_org uuid, p_event_id uuid) RETURNS bigint
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT p.post_seq FROM consentvault.arrival_place(p_org, p_event_id) p;
$$;
REVOKE ALL ON FUNCTION consentvault.arrival_post_seq(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.arrival_post_seq(uuid, uuid) TO consentvault_app, consentvault_worker, consentvault_console,
    consentvault_isolation_self_test;

-- The permission view's rank and the proof's time now read that place (same signatures as migration 0075, so the view and every
-- caller are unchanged).
CREATE OR REPLACE FUNCTION consentvault.arrival_key(p_org uuid, p_event_id uuid, p_seq bigint, p_received timestamptz) RETURNS numeric
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.round(extract(epoch FROM coalesce(p.received_at, p_received)) * 1000000) * 1e30
           + coalesce(p.post_seq, 0)::numeric * 1e15 + p_seq::numeric
      FROM (SELECT 1) one
      LEFT JOIN LATERAL consentvault.arrival_place(p_org, p_event_id) p ON true;
$$;

CREATE OR REPLACE FUNCTION consentvault.arrival_at(p_org uuid, p_event_id uuid, p_received timestamptz) RETURNS timestamptz
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce((SELECT p.received_at FROM consentvault.arrival_place(p_org, p_event_id) p), p_received);
$$;
