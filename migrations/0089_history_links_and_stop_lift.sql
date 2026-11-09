-- Pure projection, migration step 9 (specs/capture-everything/pure-projection.md, "Migration 0087": renumbered 0089). Every table that
-- cited an event of the frozen event table can cite a HISTORY event too: a column of its own with a key to post_history. No existing
-- column is dropped or changes shape, and no row of the frozen chain is touched. A stop is lifted in history_stop_lift, whose guard is
-- the check_stop_lift function generalised to read history (the same three conditions: the row is a stop of this contact point, the
-- lifting post is matched to it, and it arrived after the stop).
ALTER TABLE consentvault.confirmation_send_intent ADD COLUMN basis_history_event_id uuid;
ALTER TABLE consentvault.confirmation_send_intent ADD FOREIGN KEY (org_id, basis_history_event_id)
    REFERENCES consentvault.post_history (org_id, event_id);
ALTER TABLE consentvault.confirmation_reply ADD COLUMN history_event_id uuid;
ALTER TABLE consentvault.confirmation_reply ADD FOREIGN KEY (org_id, history_event_id)
    REFERENCES consentvault.post_history (org_id, event_id);
ALTER TABLE consentvault.event_source_post ADD COLUMN history_event_id uuid;
ALTER TABLE consentvault.event_source_post ADD FOREIGN KEY (org_id, history_event_id)
    REFERENCES consentvault.post_history (org_id, event_id);
GRANT INSERT (basis_history_event_id) ON consentvault.confirmation_send_intent TO consentvault_app;
GRANT INSERT (history_event_id) ON consentvault.confirmation_reply TO consentvault_app;
GRANT INSERT (history_event_id) ON consentvault.event_source_post TO consentvault_app;

CREATE TABLE consentvault.history_stop_lift (
    org_id          uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    stop_event_id   uuid NOT NULL,
    lifting_post_id uuid NOT NULL,
    contact_fp      text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    linked_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, stop_event_id, lifting_post_id),
    FOREIGN KEY (org_id, stop_event_id) REFERENCES consentvault.post_history (org_id, event_id),
    FOREIGN KEY (org_id, lifting_post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE INDEX history_stop_lift_contact_idx ON consentvault.history_stop_lift (org_id, contact_fp);
CREATE TRIGGER history_stop_lift_append_only BEFORE UPDATE OR DELETE ON consentvault.history_stop_lift
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER history_stop_lift_no_truncate BEFORE TRUNCATE ON consentvault.history_stop_lift
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Same function, same name and grants as migration 0071; it now serves both lift tables.
CREATE OR REPLACE FUNCTION consentvault.check_stop_lift() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    stop_at pg_catalog.timestamptz;
    post_at pg_catalog.timestamptz;
BEGIN
    IF TG_TABLE_NAME OPERATOR(pg_catalog.=) 'history_stop_lift' THEN
        SELECT h.placed_at INTO stop_at
        FROM consentvault.post_history h
        WHERE h.org_id OPERATOR(pg_catalog.=) NEW.org_id
          AND h.event_id OPERATOR(pg_catalog.=) NEW.stop_event_id
          AND h.event_type_sent OPERATOR(pg_catalog.=) ANY (ARRAY['revoke', 'suppress']::pg_catalog.text[])
          AND h.contact_fp OPERATOR(pg_catalog.=) NEW.contact_fp;
    ELSE
        SELECT e.received_at INTO stop_at
        FROM consentvault.event e
        WHERE e.org_id OPERATOR(pg_catalog.=) NEW.org_id
          AND e.event_id OPERATOR(pg_catalog.=) NEW.stop_event_id
          AND e.event_type OPERATOR(pg_catalog.=) ANY (ARRAY['revoke', 'suppress']::pg_catalog.text[])
          AND e.contact_fp OPERATOR(pg_catalog.=) NEW.contact_fp;
    END IF;
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
CREATE TRIGGER history_stop_lift_check BEFORE INSERT ON consentvault.history_stop_lift
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_stop_lift();

ALTER TABLE consentvault.history_stop_lift ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.history_stop_lift FORCE ROW LEVEL SECURITY;
CREATE POLICY history_stop_lift_tenant ON consentvault.history_stop_lift USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
CREATE POLICY history_stop_lift_read_scope ON consentvault.history_stop_lift AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_evidence()));

GRANT SELECT ON consentvault.history_stop_lift TO consentvault_app, consentvault_console;
GRANT INSERT (org_id, stop_event_id, lifting_post_id, contact_fp) ON consentvault.history_stop_lift TO consentvault_app;
