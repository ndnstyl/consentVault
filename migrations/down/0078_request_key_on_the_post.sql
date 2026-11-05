-- Reverses 0078_request_key_on_the_post.sql: an event is placed by the post that triggered it again (migration 0075's two functions are
-- restored), the two new functions are dropped, and the request keys recorded beside the posts are dropped with their table. The
-- request key stays where it always was, as an encrypted fact beside each post and a column of the event link; the posts and events
-- are untouched.
BEGIN;
CREATE OR REPLACE FUNCTION consentvault.arrival_key(p_org uuid, p_event_id uuid, p_seq bigint, p_received timestamptz) RETURNS numeric
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.round(extract(epoch FROM coalesce(p.received_at, p_received)) * 1000000) * 1e30
           + coalesce(p.seq, 0)::numeric * 1e15 + p_seq::numeric
      FROM (SELECT 1) one
      LEFT JOIN LATERAL (SELECT rp.received_at, rp.seq FROM consentvault.event_source_post s
                           JOIN consentvault.raw_post rp ON rp.org_id OPERATOR(pg_catalog.=) s.org_id AND rp.post_id OPERATOR(pg_catalog.=) s.post_id
                          WHERE s.org_id OPERATOR(pg_catalog.=) p_org AND s.event_id OPERATOR(pg_catalog.=) p_event_id
                            AND s.role OPERATOR(pg_catalog.=) 'trigger' LIMIT 1) p ON true;
$$;
CREATE OR REPLACE FUNCTION consentvault.arrival_at(p_org uuid, p_event_id uuid, p_received timestamptz) RETURNS timestamptz
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce((SELECT rp.received_at FROM consentvault.event_source_post s
                       JOIN consentvault.raw_post rp ON rp.org_id OPERATOR(pg_catalog.=) s.org_id AND rp.post_id OPERATOR(pg_catalog.=) s.post_id
                      WHERE s.org_id OPERATOR(pg_catalog.=) p_org AND s.event_id OPERATOR(pg_catalog.=) p_event_id
                        AND s.role OPERATOR(pg_catalog.=) 'trigger' LIMIT 1), p_received);
$$;
DROP FUNCTION consentvault.arrival_post_seq(uuid, uuid);
DROP FUNCTION consentvault.arrival_place(uuid, uuid);
DROP TABLE consentvault.raw_post_request;
COMMIT;
