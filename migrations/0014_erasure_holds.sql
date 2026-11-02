-- Erasure, offboarding, legal holds, legal process, operator access and restore reconciliation.
--
-- * erasure_request: a client admin asks; an operator confirms; consentvault.erase_contact(fp) deletes the one
--   contact_key row of the current organisation (no organisation argument). The fingerprint and every event stay, so
--   a returning contact still matches its old stop.
-- * legal_hold: while active, an erasure, a contact key delete and an organisation key destruction inside its scope
--   are refused here, in the database, whoever asks. A refused request is queued (erasure_request.held_by,
--   offboarding_request.steps), never dropped, and resumes when the hold is released.
-- * offboarding_request and destruction_record: the operator's offboard run and the record of what was destroyed.
-- * legal_process and operator_access: the custodian's log of outside requests and of every operator read.
-- * restore_run (platform, owner only): while a restore is unreconciled the gate refuses to record a decision, so it
--   answers 503 until reconciliation finishes.
-- * evidence_org_ids: an offboarding organisation leaves the sync and anchor jobs once its final export is taken.

-- A list of 64-hex fingerprints, for check constraints.
CREATE FUNCTION consentvault.all_fingerprints(p text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(bool_and(x ~ '^[0-9a-f]{64}$'), true) FROM unnest(p) AS x;
$$;
REVOKE ALL ON FUNCTION consentvault.all_fingerprints(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.all_fingerprints(text[]) TO consentvault_app;

-- Legal holds -----------------------------------------------------------------------------------------------------------
CREATE TABLE consentvault.legal_hold (
    org_id            uuid NOT NULL REFERENCES consentvault.organization (org_id),
    hold_id           uuid NOT NULL DEFAULT gen_random_uuid(),
    scope             text NOT NULL CHECK (scope IN ('org', 'contacts')),
    contact_fps       text[] NOT NULL DEFAULT '{}',
    set_by_kind       text NOT NULL CHECK (set_by_kind IN ('member', 'operator')),
    set_by            text NOT NULL CHECK (length(set_by) BETWEEN 1 AND 200),
    set_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    reason            text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    legal_process_id  uuid,
    set_ledger_seq    bigint,
    released_by_kind  text CHECK (released_by_kind IS NULL OR released_by_kind IN ('member', 'operator')),
    released_by       text,
    released_at       timestamptz,
    release_reason    text CHECK (release_reason IS NULL OR length(release_reason) BETWEEN 1 AND 500),
    release_ledger_seq bigint,
    PRIMARY KEY (org_id, hold_id),
    CONSTRAINT legal_hold_scope_shape CHECK (
        (scope = 'org' AND cardinality(contact_fps) = 0)
        OR (scope = 'contacts' AND cardinality(contact_fps) BETWEEN 1 AND 1000
            AND consentvault.all_fingerprints(contact_fps))),
    CONSTRAINT legal_hold_release_shape CHECK (
        (released_at IS NULL AND released_by IS NULL AND released_by_kind IS NULL AND release_reason IS NULL)
        OR (released_at IS NOT NULL AND released_by IS NOT NULL AND released_by_kind IS NOT NULL
            AND release_reason IS NOT NULL)),
    -- a hold an operator set (legal process) is released only by an operator
    CONSTRAINT legal_hold_operator_release CHECK (set_by_kind <> 'operator' OR released_by_kind IS DISTINCT FROM 'member')
);
CREATE INDEX legal_hold_active_idx ON consentvault.legal_hold (org_id) WHERE released_at IS NULL;

CREATE FUNCTION consentvault.legal_hold_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.legal_hold is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.released_at IS NOT NULL THEN
        RAISE EXCEPTION 'consentvault.legal_hold: a released hold does not change' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.org_id, NEW.hold_id, NEW.scope, NEW.contact_fps, NEW.set_by_kind, NEW.set_by, NEW.set_at, NEW.reason,
        NEW.legal_process_id, NEW.set_ledger_seq)
       IS DISTINCT FROM (OLD.org_id, OLD.hold_id, OLD.scope, OLD.contact_fps, OLD.set_by_kind, OLD.set_by, OLD.set_at,
                         OLD.reason, OLD.legal_process_id, OLD.set_ledger_seq) THEN
        RAISE EXCEPTION 'consentvault.legal_hold: only the release columns change, once' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER legal_hold_guard BEFORE UPDATE OR DELETE ON consentvault.legal_hold
    FOR EACH ROW EXECUTE FUNCTION consentvault.legal_hold_guard();
CREATE TRIGGER legal_hold_no_truncate BEFORE TRUNCATE ON consentvault.legal_hold
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- One lock per organisation for everything a hold can block: placing a hold and erasing take it, so no hold can land
-- between an erasure's hold check and its delete.
CREATE FUNCTION consentvault.lifecycle_lock() RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.current_org();
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault lifecycle: no organisation is entered' USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('consentvault.lifecycle:' || org::text));
    RETURN org;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.lifecycle_lock() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.lifecycle_lock() TO consentvault_app;

-- The first active hold of the current organisation that covers a fingerprint (NULL fingerprint: an org-scope hold).
CREATE FUNCTION consentvault.legal_hold_covering(p_contact_fp text) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT h.hold_id FROM consentvault.legal_hold h
     WHERE h.org_id = consentvault.current_org() AND h.released_at IS NULL
       AND (h.scope = 'org' OR (p_contact_fp IS NOT NULL AND p_contact_fp = ANY (h.contact_fps)))
     ORDER BY h.set_at, h.hold_id LIMIT 1;
$$;
REVOKE ALL ON FUNCTION consentvault.legal_hold_covering(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.legal_hold_covering(text) TO consentvault_app;

-- The same check for the organisation a row belongs to (the guards below run per row, whoever deletes:
-- a delete made outside any tenant, by a superuser or a job, is held exactly the same). Not granted to any role.
CREATE FUNCTION consentvault.legal_hold_on(p_org uuid, p_contact_fp text) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT h.hold_id FROM consentvault.legal_hold h
     WHERE h.org_id = p_org AND h.released_at IS NULL
       AND (h.scope = 'org' OR (p_contact_fp IS NOT NULL AND p_contact_fp = ANY (h.contact_fps)))
     ORDER BY h.set_at, h.hold_id LIMIT 1;
$$;
REVOKE ALL ON FUNCTION consentvault.legal_hold_on(uuid, text) FROM PUBLIC;

-- A contact key is deleted only outside every active hold, whoever deletes it.
CREATE FUNCTION consentvault.contact_key_hold_guard() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    h uuid := consentvault.legal_hold_on(OLD.org_id, OLD.contact_fp);
BEGIN
    IF h IS NOT NULL THEN
        RAISE EXCEPTION 'legal_hold_active:%', h USING ERRCODE = 'integrity_constraint_violation',
            DETAIL = 'a legal hold covers this contact; its key is not deleted';
    END IF;
    RETURN OLD;
END;
$$;
CREATE TRIGGER contact_key_hold_guard BEFORE DELETE ON consentvault.contact_key
    FOR EACH ROW EXECUTE FUNCTION consentvault.contact_key_hold_guard();

-- An organisation key is never scheduled for destruction or marked destroyed while any hold of the org is active.
CREATE FUNCTION consentvault.org_key_hold_guard() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    h uuid;
BEGIN
    IF NEW.status IN ('scheduled_destroy', 'destroyed') AND NEW.status IS DISTINCT FROM OLD.status THEN
        -- any active hold: destroying the organisation key destroys every held contact's data too
        SELECT x.hold_id INTO h FROM consentvault.legal_hold x
         WHERE x.org_id = NEW.org_id AND x.released_at IS NULL ORDER BY x.set_at, x.hold_id LIMIT 1;
        IF h IS NOT NULL THEN
            RAISE EXCEPTION 'legal_hold_active:%', h USING ERRCODE = 'integrity_constraint_violation',
                DETAIL = 'a legal hold covers this organisation; its key is not destroyed';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER org_key_hold_guard BEFORE UPDATE ON consentvault.org_key
    FOR EACH ROW EXECUTE FUNCTION consentvault.org_key_hold_guard();

-- Erasure requests --------------------------------------------------------------------------------------------------------
CREATE TABLE consentvault.erasure_request (
    org_id        uuid NOT NULL REFERENCES consentvault.organization (org_id),
    erasure_id    uuid NOT NULL DEFAULT gen_random_uuid(),
    contact_fp    text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    reason        text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    requested_by  uuid NOT NULL,
    requested_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    status        text NOT NULL DEFAULT 'pending_operator_confirmation'
                  CHECK (status IN ('pending_operator_confirmation', 'completed', 'declined')),
    confirmed_by  text,
    confirmed_at  timestamptz,
    held_by       uuid,
    held_since    timestamptz,
    decline_reason text CHECK (decline_reason IS NULL OR length(decline_reason) BETWEEN 1 AND 500),
    completed_at  timestamptz,
    ledger_seq    bigint,
    ledger_sha256 text CHECK (ledger_sha256 IS NULL OR ledger_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (org_id, erasure_id),
    FOREIGN KEY (org_id, held_by) REFERENCES consentvault.legal_hold (org_id, hold_id),
    CONSTRAINT erasure_request_completed_shape CHECK (
        (status = 'completed') = (completed_at IS NOT NULL AND confirmed_by IS NOT NULL AND ledger_seq IS NOT NULL)),
    CONSTRAINT erasure_request_declined_shape CHECK ((status = 'declined') = (decline_reason IS NOT NULL)),
    CONSTRAINT erasure_request_held_shape CHECK ((held_by IS NULL) = (held_since IS NULL)
                                                AND (held_by IS NULL OR status = 'pending_operator_confirmation'))
);

CREATE FUNCTION consentvault.erasure_request_guard() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    h uuid;
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.erasure_request is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF TG_OP OPERATOR(pg_catalog.=) 'INSERT' THEN
        h := consentvault.legal_hold_on(NEW.org_id, NEW.contact_fp);
        IF h IS NOT NULL THEN
            RAISE EXCEPTION 'legal_hold_active:%', h USING ERRCODE = 'integrity_constraint_violation',
                DETAIL = 'a legal hold covers this contact; the erasure request is refused';
        END IF;
        RETURN NEW;
    END IF;
    IF (NEW.org_id, NEW.erasure_id, NEW.contact_fp, NEW.reason, NEW.requested_by, NEW.requested_at)
       IS DISTINCT FROM (OLD.org_id, OLD.erasure_id, OLD.contact_fp, OLD.reason, OLD.requested_by, OLD.requested_at)
       OR OLD.status <> 'pending_operator_confirmation' THEN
        RAISE EXCEPTION 'consentvault.erasure_request: only an open request changes, and only its status columns'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER erasure_request_guard BEFORE INSERT OR UPDATE OR DELETE ON consentvault.erasure_request
    FOR EACH ROW EXECUTE FUNCTION consentvault.erasure_request_guard();
CREATE TRIGGER erasure_request_no_truncate BEFORE TRUNCATE ON consentvault.erasure_request
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Delete the current organisation's key for one contact. No organisation argument: it acts on current_org() only, and
-- needs an admin token (the operator's confirmation) or the restore job's token. Refused under a covering hold.
-- Returns true when a key row was deleted, false when there was none (already erased, or never this org's contact).
CREATE FUNCTION consentvault.erase_contact(p_contact_fp text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.lifecycle_lock();
    h   uuid;
    n   integer;
BEGIN
    IF p_contact_fp IS NULL OR p_contact_fp !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'consentvault erase: the fingerprint must be 64 hex characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF NOT coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'worker:restore'], false) THEN
        RAISE EXCEPTION 'consentvault erase: an admin or restore token is required' USING ERRCODE = 'insufficient_privilege';
    END IF;
    h := consentvault.legal_hold_covering(p_contact_fp);
    IF h IS NOT NULL THEN
        RAISE EXCEPTION 'legal_hold_active:%', h USING ERRCODE = 'integrity_constraint_violation',
            DETAIL = 'a legal hold covers this contact; its key is not deleted';
    END IF;
    DELETE FROM consentvault.contact_key k WHERE k.org_id = org AND k.contact_fp = p_contact_fp;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n > 0;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.erase_contact(text) FROM PUBLIC;

-- Offboarding -----------------------------------------------------------------------------------------------------------
CREATE TABLE consentvault.offboarding_request (
    org_id                uuid NOT NULL REFERENCES consentvault.organization (org_id),
    request_id            uuid NOT NULL DEFAULT gen_random_uuid(),
    reason                text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    requested_by          uuid,
    requested_by_operator text,
    requested_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    state                 text NOT NULL DEFAULT 'requested' CHECK (state IN ('requested', 'in_progress', 'complete')),
    steps                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    destroy_after         timestamptz,
    final_export_at       timestamptz,
    final_export_sha256   text CHECK (final_export_sha256 IS NULL OR final_export_sha256 ~ '^[0-9a-f]{64}$'),
    final_export_key      text,
    final_export_wrapped  bytea,
    PRIMARY KEY (org_id, request_id),
    CONSTRAINT offboarding_request_by CHECK ((requested_by IS NULL) <> (requested_by_operator IS NULL)),
    CONSTRAINT offboarding_request_export_shape CHECK (
        (final_export_at IS NULL) = (final_export_sha256 IS NULL)
        AND (final_export_at IS NULL) = (final_export_key IS NULL)
        AND (final_export_at IS NULL) = (final_export_wrapped IS NULL))
);
CREATE UNIQUE INDEX offboarding_request_open_idx ON consentvault.offboarding_request (org_id) WHERE state <> 'complete';

CREATE FUNCTION consentvault.offboarding_request_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.offboarding_request is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.org_id, NEW.request_id, NEW.reason, NEW.requested_by, NEW.requested_by_operator, NEW.requested_at)
       IS DISTINCT FROM (OLD.org_id, OLD.request_id, OLD.reason, OLD.requested_by, OLD.requested_by_operator,
                         OLD.requested_at)
       OR OLD.state = 'complete'
       OR (OLD.final_export_at IS NOT NULL AND (NEW.final_export_at, NEW.final_export_sha256, NEW.final_export_key,
           NEW.final_export_wrapped) IS DISTINCT FROM (OLD.final_export_at, OLD.final_export_sha256,
           OLD.final_export_key, OLD.final_export_wrapped)) THEN
        RAISE EXCEPTION 'consentvault.offboarding_request: only an open request advances, and a taken export never changes'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER offboarding_request_guard BEFORE UPDATE OR DELETE ON consentvault.offboarding_request
    FOR EACH ROW EXECUTE FUNCTION consentvault.offboarding_request_guard();
CREATE TRIGGER offboarding_request_no_truncate BEFORE TRUNCATE ON consentvault.offboarding_request
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- What was destroyed, when, and under what exception. Append-only.
CREATE TABLE consentvault.destruction_record (
    org_id        uuid NOT NULL REFERENCES consentvault.organization (org_id),
    record_id     uuid NOT NULL DEFAULT gen_random_uuid(),
    request_id    uuid NOT NULL,
    kind          text NOT NULL CHECK (kind IN ('scheduled', 'held', 'resumed', 'destroyed')),
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    key_refs      text[] NOT NULL DEFAULT '{}',
    destroy_after timestamptz,
    export_sha256 text CHECK (export_sha256 IS NULL OR export_sha256 ~ '^[0-9a-f]{64}$'),
    hold_id       uuid,
    detail        jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (org_id, record_id),
    FOREIGN KEY (org_id, request_id) REFERENCES consentvault.offboarding_request (org_id, request_id)
);
CREATE TRIGGER destruction_record_no_change BEFORE UPDATE OR DELETE ON consentvault.destruction_record
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER destruction_record_no_truncate BEFORE TRUNCATE ON consentvault.destruction_record
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Legal process and operator access ------------------------------------------------------------------------------------
CREATE TABLE consentvault.legal_process (
    org_id                  uuid NOT NULL REFERENCES consentvault.organization (org_id),
    process_id              uuid NOT NULL DEFAULT gen_random_uuid(),
    type                    text NOT NULL CHECK (type IN ('subpoena', 'court_order', 'search_warrant', 'regulator_request',
                                                          'law_enforcement_request', 'civil_discovery', 'other')),
    received_at             timestamptz NOT NULL,
    received_via            text NOT NULL CHECK (length(received_via) BETWEEN 1 AND 200),
    requester               text NOT NULL CHECK (length(requester) BETWEEN 1 AND 300),
    scope_summary           text NOT NULL CHECK (length(scope_summary) BETWEEN 1 AND 2000),
    response_deadline       timestamptz,
    handled_by              text NOT NULL,
    hold_id                 uuid,
    client_notified_at      timestamptz,
    notice_prohibited_basis text CHECK (notice_prohibited_basis IS NULL OR length(notice_prohibited_basis) BETWEEN 1 AND 1000),
    response_ref            text CHECK (response_ref IS NULL OR length(response_ref) BETWEEN 1 AND 500),
    produced_sha256         text[] NOT NULL DEFAULT '{}',
    closed_at               timestamptz,
    created_at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, process_id),
    FOREIGN KEY (org_id, hold_id) REFERENCES consentvault.legal_hold (org_id, hold_id),
    CONSTRAINT legal_process_notice_shape CHECK (client_notified_at IS NULL OR notice_prohibited_basis IS NULL),
    CONSTRAINT legal_process_close_shape CHECK (closed_at IS NULL OR (response_ref IS NOT NULL
        AND (client_notified_at IS NOT NULL OR notice_prohibited_basis IS NOT NULL)))
);
CREATE FUNCTION consentvault.legal_process_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.legal_process is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.org_id, NEW.process_id, NEW.type, NEW.received_at, NEW.received_via, NEW.requester, NEW.scope_summary,
        NEW.response_deadline, NEW.handled_by, NEW.created_at)
       IS DISTINCT FROM (OLD.org_id, OLD.process_id, OLD.type, OLD.received_at, OLD.received_via, OLD.requester,
                         OLD.scope_summary, OLD.response_deadline, OLD.handled_by, OLD.created_at)
       OR OLD.closed_at IS NOT NULL
       OR (OLD.hold_id IS NOT NULL AND NEW.hold_id IS DISTINCT FROM OLD.hold_id)
       OR (OLD.client_notified_at IS NOT NULL AND NEW.client_notified_at IS DISTINCT FROM OLD.client_notified_at)
       OR (OLD.notice_prohibited_basis IS NOT NULL AND NEW.notice_prohibited_basis IS DISTINCT FROM OLD.notice_prohibited_basis) THEN
        RAISE EXCEPTION 'consentvault.legal_process: an entry only gains its hold, notice, production and close, once each'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER legal_process_guard BEFORE UPDATE OR DELETE ON consentvault.legal_process
    FOR EACH ROW EXECUTE FUNCTION consentvault.legal_process_guard();
CREATE TRIGGER legal_process_no_truncate BEFORE TRUNCATE ON consentvault.legal_process
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

CREATE TABLE consentvault.operator_access (
    org_id             uuid NOT NULL REFERENCES consentvault.organization (org_id),
    access_id          uuid NOT NULL DEFAULT gen_random_uuid(),
    operator_id        text NOT NULL CHECK (length(operator_id) BETWEEN 1 AND 200),
    reason             text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    approved_by_client uuid,
    emergency          boolean NOT NULL DEFAULT false,
    client_notified_at timestamptz,
    legal_process_id   uuid,
    opened_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    closed_at          timestamptz,
    PRIMARY KEY (org_id, access_id),
    FOREIGN KEY (org_id, legal_process_id) REFERENCES consentvault.legal_process (org_id, process_id),
    CONSTRAINT operator_access_basis CHECK (
        (approved_by_client IS NOT NULL AND NOT emergency)
        OR (approved_by_client IS NULL AND emergency AND client_notified_at IS NOT NULL))
);
CREATE FUNCTION consentvault.operator_access_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.operator_access is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.closed_at IS NOT NULL OR (NEW.org_id, NEW.access_id, NEW.operator_id, NEW.reason, NEW.approved_by_client,
        NEW.emergency, NEW.client_notified_at, NEW.legal_process_id, NEW.opened_at)
       IS DISTINCT FROM (OLD.org_id, OLD.access_id, OLD.operator_id, OLD.reason, OLD.approved_by_client, OLD.emergency,
                         OLD.client_notified_at, OLD.legal_process_id, OLD.opened_at) THEN
        RAISE EXCEPTION 'consentvault.operator_access: an access only closes, once' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER operator_access_guard BEFORE UPDATE OR DELETE ON consentvault.operator_access
    FOR EACH ROW EXECUTE FUNCTION consentvault.operator_access_guard();
CREATE TRIGGER operator_access_no_truncate BEFORE TRUNCATE ON consentvault.operator_access
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Restore reconciliation (platform, owner only) -------------------------------------------------------------------------
CREATE TABLE consentvault.restore_run (
    run_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    restore_point timestamptz NOT NULL,
    started_by    text NOT NULL,
    started_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    state         text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'complete')),
    finished_at   timestamptz,
    report        jsonb,
    CONSTRAINT restore_run_finished_shape CHECK ((state = 'complete') = (finished_at IS NOT NULL AND report IS NOT NULL))
);
CREATE UNIQUE INDEX restore_run_one_pending_idx ON consentvault.restore_run ((true)) WHERE state = 'pending';
REVOKE ALL ON consentvault.restore_run FROM PUBLIC;

CREATE FUNCTION consentvault.restore_pending() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM consentvault.restore_run WHERE state = 'pending');
$$;
REVOKE ALL ON FUNCTION consentvault.restore_pending() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.restore_pending() TO consentvault_app, consentvault_worker;

-- The gate records every answer it gives; while a restore is unreconciled the record is refused, so the gate answers
-- 503 rather than an answer read from a database that may be missing stops.
CREATE FUNCTION consentvault.gate_decision_restore_guard() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF consentvault.restore_pending() THEN
        RAISE EXCEPTION 'consentvault gate: the database was restored and is not yet reconciled'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER gate_decision_restore_guard BEFORE INSERT ON consentvault.gate_decision
    FOR EACH ROW EXECUTE FUNCTION consentvault.gate_decision_restore_guard();

-- Row-level security ------------------------------------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['legal_hold', 'erasure_request', 'offboarding_request', 'destruction_record',
                             'legal_process', 'operator_access'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
    END LOOP;
END
$$;

-- Jobs: an offboarding organisation leaves the evidence jobs once its final export is taken; restore covers every org --
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
GRANT SELECT (org_id, state, final_export_at) ON consentvault.offboarding_request TO consentvault_operator;

CREATE OR REPLACE FUNCTION consentvault.evidence_org_ids() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT o.org_id FROM consentvault.organization o
     WHERE o.status <> 'closed'
       AND NOT (o.status = 'offboarding' AND EXISTS (
           SELECT 1 FROM consentvault.offboarding_request r
            WHERE r.org_id = o.org_id AND r.final_export_at IS NOT NULL))
     ORDER BY o.org_id;
$$;

CREATE FUNCTION consentvault.restore_org_ids() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT org_id FROM consentvault.organization ORDER BY org_id;
$$;
ALTER FUNCTION consentvault.restore_org_ids() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.restore_org_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.restore_org_ids() TO CURRENT_USER;

REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;

-- Grants to the runtime role (client admins ask; operators act on the owner's connection) ------------------------------
GRANT SELECT, INSERT ON consentvault.legal_hold TO consentvault_app;
GRANT UPDATE (released_by_kind, released_by, released_at, release_reason, release_ledger_seq)
    ON consentvault.legal_hold TO consentvault_app;
GRANT SELECT, INSERT ON consentvault.erasure_request TO consentvault_app;
GRANT UPDATE (held_by, held_since) ON consentvault.erasure_request TO consentvault_app;
GRANT SELECT, INSERT ON consentvault.offboarding_request TO consentvault_app;
GRANT SELECT ON consentvault.destruction_record TO consentvault_app;
