-- A stop is lifted only by the person: a later consent post from them on the same contact point.
--
-- stop_lift links a stop (an event written by a stop page, a STOP text, an erasure or an import) to the raw post that
-- lifted it. A row is accepted only when the lifting post is matched to the stop's own contact point (same keyed
-- fingerprint) and arrived after the stop on the database's clock. Whether that post's consent value equals the value its
-- form's box sends when ticked is decided in code (consentvault/lift.py), where the stored value can be opened; the
-- database cannot read an encrypted value. The stop stays on the record; nothing is deleted or changed.
--
-- No release event can be written any more: a release was a decision by the vault about whose grant lifts whose stop, and a
-- decision of that kind belongs to nobody. check_release_ref refuses every release row. Release rows already in a ledger are
-- history, still verified by the chain, and are shown as the history lines they are.
--
-- The gate_decision evidence-status check admits the plain labels of the contact check (records_found, no_record_found,
-- unavailable:<cause>); the earlier labels stay valid for the rows already written.
--
-- check_release_ref is a pinned guard function. On a vault whose guards are already pinned this migration runs as the superuser
-- (the documented break-glass) followed by consentvault_guard.repin(), exactly as 0068 did.
BEGIN;

CREATE TABLE consentvault.stop_lift (
    org_id          uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    stop_event_id   uuid NOT NULL,
    lifting_post_id uuid NOT NULL,
    contact_fp      text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    linked_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, stop_event_id, lifting_post_id),
    FOREIGN KEY (org_id, stop_event_id) REFERENCES consentvault.event (org_id, event_id),
    FOREIGN KEY (org_id, lifting_post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE INDEX stop_lift_contact_idx ON consentvault.stop_lift (org_id, contact_fp);
CREATE TRIGGER stop_lift_append_only BEFORE UPDATE OR DELETE ON consentvault.stop_lift
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER stop_lift_no_truncate BEFORE TRUNCATE ON consentvault.stop_lift
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

CREATE FUNCTION consentvault.check_stop_lift() RETURNS trigger LANGUAGE plpgsql
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
REVOKE ALL ON FUNCTION consentvault.check_stop_lift() FROM PUBLIC;
CREATE TRIGGER stop_lift_check BEFORE INSERT ON consentvault.stop_lift
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_stop_lift();

ALTER TABLE consentvault.stop_lift ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.stop_lift FORCE ROW LEVEL SECURITY;
CREATE POLICY stop_lift_tenant ON consentvault.stop_lift USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
CREATE POLICY stop_lift_read_scope ON consentvault.stop_lift AS RESTRICTIVE FOR SELECT
    USING ((SELECT consentvault.may_read_evidence()));

GRANT SELECT ON consentvault.stop_lift TO consentvault_app, consentvault_console;
GRANT INSERT (org_id, stop_event_id, lifting_post_id, contact_fp) ON consentvault.stop_lift TO consentvault_app;

-- No release event is written any more.
CREATE OR REPLACE FUNCTION consentvault.check_release_ref() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.event_type OPERATOR(pg_catalog.<>) 'release' THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'consentvault release: no release event can be written; a stop is lifted only by a later consent post from the person'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

-- The contact check's plain labels join the earlier ones.
ALTER TABLE consentvault.gate_decision DROP CONSTRAINT gate_decision_evidence_status_check;
ALTER TABLE consentvault.gate_decision ADD CONSTRAINT gate_decision_evidence_status_check
    CHECK (evidence_status ~ '^(consent_record_found|stop_on_record|no_record|record_incomplete:.+|unavailable:.+|records_found|no_record_found)$');

COMMIT;
