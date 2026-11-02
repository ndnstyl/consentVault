-- Capture, gate and proof for many organisations: the tables the tenant API writes, and the startup check that the
-- vault's owner-rights functions and tables are still owned by roles that row-level security binds. Wording versions,
-- policies, checklists and rule references are 0005's (admin lane); this file only reads them.
--
-- Every tenant table follows the conventions of 0002: org_id NOT NULL with a foreign key, ENABLE and FORCE ROW LEVEL
-- SECURITY, one policy on (SELECT consentvault.current_org()), random UUID ids, nothing personal in a clear column,
-- append-only where the row is evidence. No column is added to seal, chain_head, contact_log or review.

-- Owner-rights check -----------------------------------------------------------------------------------------------
-- A restore made without owners (pg_restore --no-owner as a superuser) hands every SECURITY DEFINER function and every
-- table to a role that bypasses row-level security, which turns each owner-rights function into a cross-organisation
-- path. This lists every such problem; require_multi_tenant() refuses while any row is returned.
CREATE FUNCTION consentvault.owner_rights_violations()
    RETURNS TABLE (object_kind text, object_name text, owner_name text, problem text)
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH ns AS (
        SELECT n.oid, n.nspowner FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.=) 'consentvault'
    ), op AS (
        SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) 'consentvault_operator'
    )
    SELECT 'schema', 'consentvault', r.rolname, 'the schema owner is a superuser or BYPASSRLS'
      FROM ns JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) ns.nspowner
     WHERE r.rolsuper OR r.rolbypassrls
    UNION ALL
    SELECT 'role', 'consentvault_operator', r.rolname, 'the operator role is a superuser'
      FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) 'consentvault_operator' AND r.rolsuper
    UNION ALL
    SELECT 'function', p.oid::pg_catalog.regprocedure::pg_catalog.text, r.rolname,
           'an owner-rights function is owned by a role other than the schema owner or consentvault_operator'
      FROM pg_catalog.pg_proc p
      JOIN ns ON p.pronamespace OPERATOR(pg_catalog.=) ns.oid
      JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) p.proowner
     WHERE p.prosecdef
       AND p.proowner OPERATOR(pg_catalog.<>) ns.nspowner
       AND p.proowner OPERATOR(pg_catalog.<>) ALL (ARRAY(SELECT oid FROM op))
    UNION ALL
    SELECT 'table', c.oid::pg_catalog.regclass::pg_catalog.text, r.rolname,
           'a row-secured table is owned by a superuser or BYPASSRLS role, or does not FORCE row-level security'
      FROM pg_catalog.pg_class c
      JOIN ns ON c.relnamespace OPERATOR(pg_catalog.=) ns.oid
      JOIN pg_catalog.pg_roles r ON r.oid OPERATOR(pg_catalog.=) c.relowner
     WHERE c.relkind IN ('r', 'p') AND c.relrowsecurity
       AND (r.rolsuper OR r.rolbypassrls OR NOT c.relforcerowsecurity);
$$;
REVOKE ALL ON FUNCTION consentvault.owner_rights_violations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.owner_rights_violations() TO consentvault_app, consentvault_worker;

CREATE OR REPLACE FUNCTION consentvault.require_multi_tenant() RETURNS void
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v record;
BEGIN
    IF (SELECT mode FROM consentvault.tenancy_setting WHERE singleton) IS DISTINCT FROM 'multi' THEN
        RAISE EXCEPTION 'consentvault tenancy: this vault is in single mode; a multi-tenant service must not serve it'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    SELECT * INTO v FROM consentvault.owner_rights_violations() LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION 'consentvault tenancy: % % (owner %): %', v.object_kind, v.object_name, v.owner_name, v.problem
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
END;
$$;

-- The receipt of one event of the current organisation (no personal field): a capture token may not read evidence
-- rows, but it must be able to sign the receipt of the row it just wrote.
CREATE FUNCTION consentvault.receipt_of(p_event_id uuid)
    RETURNS TABLE (seq bigint, row_hash text, received_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT e.seq, e.row_hash, e.received_at FROM consentvault.event e
     WHERE e.org_id = consentvault.current_org() AND e.event_id = p_event_id;
$$;
REVOKE ALL ON FUNCTION consentvault.receipt_of(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.receipt_of(uuid) TO consentvault_app;

-- Evidence objects -------------------------------------------------------------------------------------------------
-- The pipeline allocates an object id, records it as pending (its own transaction), writes the encrypted evidence
-- object to write-once storage, then commits the ledger row and marks the object committed in one transaction.
-- A pending object past the reconciliation grace is marked uncommitted: never counted as an event, kept until its
-- retention ends. Status is the only thing that changes, and only forward.
CREATE TABLE consentvault.evidence_object (
    org_id       uuid NOT NULL REFERENCES consentvault.organization (org_id),
    object_id    uuid NOT NULL,
    object_key   text NOT NULL CHECK (length(object_key) BETWEEN 1 AND 900),
    contact_fp   text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    retain_until timestamptz NOT NULL,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'committed', 'uncommitted')),
    event_id     uuid,
    sha256       text CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    created_at   timestamptz NOT NULL DEFAULT now(),
    settled_at   timestamptz,
    PRIMARY KEY (org_id, object_id),
    UNIQUE (org_id, object_key),
    FOREIGN KEY (org_id, event_id) REFERENCES consentvault.event (org_id, event_id),
    CONSTRAINT evidence_object_settled_shape CHECK (
        (status = 'pending' AND event_id IS NULL AND settled_at IS NULL)
        OR (status = 'committed' AND event_id IS NOT NULL AND sha256 IS NOT NULL AND settled_at IS NOT NULL)
        OR (status = 'uncommitted' AND event_id IS NULL AND settled_at IS NOT NULL)
    )
);
CREATE INDEX evidence_object_pending_idx ON consentvault.evidence_object (org_id, created_at) WHERE status = 'pending';

CREATE FUNCTION consentvault.evidence_object_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE'
       OR OLD.status OPERATOR(pg_catalog.<>) 'pending'
       OR NEW.status OPERATOR(pg_catalog.=) 'pending'
       OR NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.object_id IS DISTINCT FROM OLD.object_id
       OR NEW.object_key IS DISTINCT FROM OLD.object_key OR NEW.contact_fp IS DISTINCT FROM OLD.contact_fp
       OR NEW.retain_until IS DISTINCT FROM OLD.retain_until OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'consentvault evidence object: only a pending object may be settled, once, as committed or uncommitted'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER evidence_object_guard BEFORE UPDATE OR DELETE ON consentvault.evidence_object
    FOR EACH ROW EXECUTE FUNCTION consentvault.evidence_object_guard();
CREATE TRIGGER evidence_object_no_truncate BEFORE TRUNCATE ON consentvault.evidence_object
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Gate decisions ---------------------------------------------------------------------------------------------------
-- Every gate answer, partitioned by month on its time; append-only. Evidence status describes the records; the
-- policy action is the client's approved policy (NULL when none is approved). Never a legal conclusion.
CREATE TABLE consentvault.gate_decision (
    org_id          uuid NOT NULL REFERENCES consentvault.organization (org_id),
    decision_id     uuid NOT NULL DEFAULT gen_random_uuid(),
    at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    contact_fp      text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    channel         text NOT NULL CHECK (channel ~ '^[a-z][a-z_]{0,31}$'),
    purpose         text NOT NULL CHECK (purpose ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    evidence_status text NOT NULL CHECK (evidence_status ~ '^(consent_record_found|stop_on_record|no_record|record_incomplete:.+|unavailable:.+)$'),
    policy_action   text CHECK (policy_action IN ('proceed', 'hold')),
    policy_version  integer,
    approved_by     text,
    approved_at     timestamptz,
    basis_event_ids uuid[] NOT NULL DEFAULT '{}',
    reasons         text[] NOT NULL DEFAULT '{}',
    requested_by    text,
    batch_id        uuid,
    PRIMARY KEY (org_id, decision_id, at),
    CONSTRAINT gate_decision_policy_shape CHECK ((policy_action IS NULL) = (policy_version IS NULL)
                                                 OR evidence_status LIKE 'unavailable:%'),
    CONSTRAINT gate_decision_stop_holds CHECK (evidence_status <> 'stop_on_record' OR policy_action IS DISTINCT FROM 'proceed')
) PARTITION BY RANGE (at);
CREATE INDEX gate_decision_contact_idx ON consentvault.gate_decision (org_id, contact_fp, at);
CREATE TABLE consentvault.gate_decision_default PARTITION OF consentvault.gate_decision DEFAULT;

CREATE TRIGGER gate_decision_append_only BEFORE UPDATE OR DELETE ON consentvault.gate_decision
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();

-- Monthly partitions are made ahead by the worker (and by this migration for the current and next two months).
-- A partition is never reached directly: row security and grants live on the parent, and each partition forces row
-- security with no policy, so a direct read of a partition sees nothing.
CREATE FUNCTION consentvault.ensure_gate_decision_partitions(p_months_ahead integer) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    m     date := date_trunc('month', now())::date;
    i     integer;
    lo    date;
    name  text;
    made  integer := 0;
BEGIN
    IF p_months_ahead IS NULL OR p_months_ahead < 0 OR p_months_ahead > 24 THEN
        RAISE EXCEPTION 'consentvault gate decisions: months ahead must be 0 to 24' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR i IN 0..p_months_ahead LOOP
        lo := (m + make_interval(months => i))::date;
        name := 'gate_decision_' || to_char(lo, 'YYYY_MM');
        IF to_regclass('consentvault.' || name) IS NULL THEN
            EXECUTE format('CREATE TABLE consentvault.%I PARTITION OF consentvault.gate_decision FOR VALUES FROM (%L) TO (%L)',
                           name, lo, (lo + interval '1 month')::date);
            EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', name);
            EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', name);
            made := made + 1;
        END IF;
    END LOOP;
    RETURN made;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.ensure_gate_decision_partitions(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.ensure_gate_decision_partitions(integer) TO consentvault_worker;
SELECT consentvault.ensure_gate_decision_partitions(2);

-- Client-supplied evidence: EBR records and DNC registry scrub results --------------------------------------------
-- Stored as the client supplied them, with who sent them and when; supporting references only as ciphertext under
-- the contact's key. Nothing here states whether a relationship qualifies or whether contact is permitted.
CREATE TABLE consentvault.ebr_record (
    org_id            uuid NOT NULL REFERENCES consentvault.organization (org_id),
    ebr_id            uuid NOT NULL,
    contact_fp        text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    relationship_type text NOT NULL CHECK (relationship_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    started_on        date NOT NULL,
    ended_on          date CHECK (ended_on IS NULL OR ended_on >= started_on),
    evidence_refs_ct  bytea,
    source            text NOT NULL CHECK (length(source) BETWEEN 1 AND 200),
    recorded_by       text NOT NULL CHECK (length(recorded_by) BETWEEN 1 AND 200),
    recorded_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, ebr_id)
);
CREATE INDEX ebr_record_contact_idx ON consentvault.ebr_record (org_id, contact_fp);

CREATE TABLE consentvault.dnc_scrub_result (
    org_id          uuid NOT NULL REFERENCES consentvault.organization (org_id),
    scrub_id        uuid NOT NULL,
    contact_fp      text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    registry        text NOT NULL CHECK (registry ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    scrubbed_at     timestamptz NOT NULL,
    result          text NOT NULL CHECK (result IN ('listed', 'not_listed')),
    provider        text NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
    evidence_ref_ct bytea,
    recorded_by     text NOT NULL CHECK (length(recorded_by) BETWEEN 1 AND 200),
    recorded_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, scrub_id)
);
CREATE INDEX dnc_scrub_result_contact_idx ON consentvault.dnc_scrub_result (org_id, contact_fp);

CREATE TRIGGER ebr_record_append_only BEFORE UPDATE OR DELETE ON consentvault.ebr_record
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER ebr_record_no_truncate BEFORE TRUNCATE ON consentvault.ebr_record
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER dnc_scrub_result_append_only BEFORE UPDATE OR DELETE ON consentvault.dnc_scrub_result
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER dnc_scrub_result_no_truncate BEFORE TRUNCATE ON consentvault.dnc_scrub_result
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Row-level security ------------------------------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['evidence_object', 'gate_decision', 'ebr_record', 'dnc_scrub_result'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
    END LOOP;
    -- the default partition is never reached directly either
    ALTER TABLE consentvault.gate_decision_default ENABLE ROW LEVEL SECURITY;
    ALTER TABLE consentvault.gate_decision_default FORCE ROW LEVEL SECURITY;
    -- gate decisions are read back only by read scopes (a capture token writes events and never sees answers)
    CREATE POLICY gate_decision_read_scope ON consentvault.gate_decision AS RESTRICTIVE FOR SELECT
        USING ((SELECT consentvault.may_read_evidence()));
END
$$;

-- Grants (every column the runtime role touches is named; condition 4 of the tenancy review) ------------------------
GRANT SELECT, INSERT ON consentvault.evidence_object TO consentvault_app;
GRANT UPDATE (status, event_id, sha256, settled_at) ON consentvault.evidence_object TO consentvault_app;
GRANT SELECT, UPDATE (status, settled_at) ON consentvault.evidence_object TO consentvault_worker;
GRANT SELECT, INSERT ON consentvault.gate_decision TO consentvault_app;
GRANT INSERT ON consentvault.ebr_record, consentvault.dnc_scrub_result TO consentvault_app;
