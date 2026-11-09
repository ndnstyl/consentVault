-- Reverses 0079_restored_copy_original_arrival.sql: an event is placed by the receipt time of its post again (migration 0078's
-- arrival_place is restored) and the original-arrival rows are dropped with their table. The posts and events are untouched.
BEGIN;
CREATE OR REPLACE FUNCTION consentvault.arrival_place(p_org uuid, p_event_id uuid) RETURNS TABLE (received_at timestamptz, post_seq bigint)
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
DROP TABLE consentvault.raw_post_original_arrival;
COMMIT;
