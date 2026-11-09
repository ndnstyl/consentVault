-- A post stored again in its owner's organisation is placed at its ORIGINAL arrival (specs/capture-everything/one-door.md,
-- addendum point 4, review round 4). When the site-key lookup failed at arrival the post was stored in the home organisation; the
-- projection later stores it again in the organisation the key belongs to, and the event cites the new copy. The new copy's own
-- receipt time is when it was stored again, not when the request arrived, so the event would sit later in a person's history than
-- the request did.
--
-- The original arrival is a fact about the copy, written beside it when it is stored again: one append-only row per post, in the
-- copy's own organisation (the original lives in another one, and no row crosses organisations). arrival_place reads the earlier
-- of the post's own receipt time and that row. The post itself is never touched.
CREATE TABLE consentvault.raw_post_original_arrival (
    org_id      uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    post_id     uuid NOT NULL,
    arrived_at  timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, post_id),
    FOREIGN KEY (org_id, post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE TRIGGER raw_post_original_arrival_append_only BEFORE UPDATE OR DELETE ON consentvault.raw_post_original_arrival
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER raw_post_original_arrival_no_truncate BEFORE TRUNCATE ON consentvault.raw_post_original_arrival
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

ALTER TABLE consentvault.raw_post_original_arrival ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.raw_post_original_arrival FORCE ROW LEVEL SECURITY;
CREATE POLICY raw_post_original_arrival_tenant ON consentvault.raw_post_original_arrival USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
CREATE POLICY raw_post_original_arrival_read_scope ON consentvault.raw_post_original_arrival AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_evidence()));

GRANT SELECT ON consentvault.raw_post_original_arrival TO consentvault_app, consentvault_console;
GRANT INSERT (org_id, post_id, arrived_at) ON consentvault.raw_post_original_arrival TO consentvault_app;

-- Same signature, same grants as migration 0078; the time of a post that was stored again is the earlier of its own receipt time
-- and the arrival recorded for it.
CREATE OR REPLACE FUNCTION consentvault.arrival_place(p_org uuid, p_event_id uuid) RETURNS TABLE (received_at timestamptz, post_seq bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT LEAST(rp.received_at, coalesce(oa.arrived_at, rp.received_at)), rp.seq
      FROM consentvault.raw_post rp
      LEFT JOIN consentvault.raw_post_original_arrival oa
             ON oa.org_id OPERATOR(pg_catalog.=) rp.org_id AND oa.post_id OPERATOR(pg_catalog.=) rp.post_id
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
