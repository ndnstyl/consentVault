-- Reverses 0089_history_links_and_stop_lift.sql: the history lift table and the three history link columns are dropped, and
-- check_stop_lift is the migration 0071 function again. On the pinned guards this runs as the superuser followed by
-- consentvault_guard.repin(), exactly as 0068 and 0071 did. The event table and its tables are untouched.
BEGIN;
DROP TABLE consentvault.history_stop_lift;
ALTER TABLE consentvault.event_source_post DROP COLUMN history_event_id;
ALTER TABLE consentvault.confirmation_reply DROP COLUMN history_event_id;
ALTER TABLE consentvault.confirmation_send_intent DROP COLUMN basis_history_event_id;
CREATE OR REPLACE FUNCTION consentvault.check_stop_lift() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    stop_at pg_catalog.timestamptz;
    post_at pg_catalog.timestamptz;
BEGIN
    SELECT e.received_at INTO stop_at
    FROM consentvault.event e
    WHERE e.org_id OPERATOR(pg_catalog.=) NEW.org_id
      AND e.event_id OPERATOR(pg_catalog.=) NEW.stop_event_id
      AND e.event_type OPERATOR(pg_catalog.=) ANY (ARRAY['revoke', 'suppress']::pg_catalog.text[])
      AND e.contact_fp OPERATOR(pg_catalog.=) NEW.contact_fp;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault stop lift: the stop named is not a stop of this contact point'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM consentvault.raw_post_match m
                   WHERE m.org_id OPERATOR(pg_catalog.=) NEW.org_id
                     AND m.post_id OPERATOR(pg_catalog.=) NEW.lifting_post_id
                     AND m.status OPERATOR(pg_catalog.=) 'matched'
                     AND m.contact_fp OPERATOR(pg_catalog.=) NEW.contact_fp) THEN
        RAISE EXCEPTION 'consentvault stop lift: the lifting post is not matched to the same contact point'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    SELECT p.received_at INTO post_at
    FROM consentvault.raw_post p
    WHERE p.org_id OPERATOR(pg_catalog.=) NEW.org_id AND p.post_id OPERATOR(pg_catalog.=) NEW.lifting_post_id;
    IF post_at OPERATOR(pg_catalog.<=) stop_at THEN
        RAISE EXCEPTION 'consentvault stop lift: the lifting post did not arrive after the stop'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
COMMIT;
