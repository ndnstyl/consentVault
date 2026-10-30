-- Gag safety: a legal process the customer has not been told of (notice prohibited, or not yet decided) and the holds an
-- operator places never reach a surface the tenant runtime role reads by name.
--
-- 1. hold_disclosure(hold) answers how the tenant may see a hold: 'member' (its own), 'operator' (a neutral hold, no reason
--    text) or 'undisclosed' (a legal-process hold the customer has not been told of). The code reads it on the tenant's
--    path, which cannot read legal_process.
-- 2. The runtime role reads no undisclosed legal-process hold row, and never the reason, the release reason or the
--    process link of any hold. It reads no hold id on an erasure request or a destruction record (erasure_hold names
--    the client's own hold only).
-- 3. An erasure request is refused at insert only under the client's own hold. Under an operator's hold it is recorded and
--    queued as a neutral held state (the key delete stays refused by contact_key_hold_guard and erase_contact).
-- 4. An emergency operator access opens without a customer notice only under a legal process whose notice is prohibited.
--
-- No column of seal, chain_head, contact_log or review changes.

-- 1. How the tenant may see a hold -------------------------------------------------------------------------------------
CREATE FUNCTION consentvault.legal_process_disclosed(p_org uuid, p_process uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce((SELECT p.client_notified_at IS NOT NULL FROM consentvault.legal_process p
                      WHERE p.org_id = p_org AND p.process_id = p_process), false);
$$;
REVOKE ALL ON FUNCTION consentvault.legal_process_disclosed(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.legal_process_disclosed(uuid, uuid) TO consentvault_app;

CREATE FUNCTION consentvault.hold_disclosure(p_hold uuid) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN h.set_by_kind = 'member' THEN 'member'
                WHEN h.legal_process_id IS NOT NULL
                     AND NOT consentvault.legal_process_disclosed(h.org_id, h.legal_process_id) THEN 'undisclosed'
                ELSE 'operator' END
      FROM consentvault.legal_hold h
     WHERE h.org_id = consentvault.current_org() AND h.hold_id = p_hold;
$$;
REVOKE ALL ON FUNCTION consentvault.hold_disclosure(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.hold_disclosure(uuid) TO consentvault_app;

-- 2. What the runtime role reads -----------------------------------------------------------------------------------------
CREATE POLICY legal_hold_tenant_disclosed ON consentvault.legal_hold AS RESTRICTIVE FOR SELECT TO consentvault_app
    USING (legal_process_id IS NULL OR consentvault.legal_process_disclosed(org_id, legal_process_id));

REVOKE SELECT ON consentvault.legal_hold FROM consentvault_app;
GRANT SELECT (org_id, hold_id, scope, contact_fps, set_by_kind, set_by, set_at, set_ledger_seq, released_by_kind,
              released_by, released_at, release_ledger_seq) ON consentvault.legal_hold TO consentvault_app;

-- An erasure request names its hold only to the client's own hold; the runtime role reads the held state, never the id.
REVOKE SELECT ON consentvault.erasure_request FROM consentvault_app;
GRANT SELECT (org_id, erasure_id, contact_fp, reason, requested_by, requested_at, status, confirmed_by, confirmed_at,
              held_since, decline_reason, completed_at, ledger_seq, ledger_sha256, wait_reason, wait_since)
    ON consentvault.erasure_request TO consentvault_app;

CREATE FUNCTION consentvault.erasure_hold(p_erasure uuid) RETURNS TABLE (disclosure text, hold_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT d.v, CASE WHEN d.v = 'member' THEN r.held_by END
      FROM consentvault.erasure_request r
     CROSS JOIN LATERAL (SELECT consentvault.hold_disclosure(r.held_by) AS v) d
     WHERE r.org_id = consentvault.current_org() AND r.erasure_id = p_erasure AND r.held_by IS NOT NULL;
$$;
REVOKE ALL ON FUNCTION consentvault.erasure_hold(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.erasure_hold(uuid) TO consentvault_app;

REVOKE SELECT ON consentvault.destruction_record FROM consentvault_app;
GRANT SELECT (org_id, record_id, request_id, kind, created_at, key_refs, destroy_after, export_sha256, detail)
    ON consentvault.destruction_record TO consentvault_app;

-- 3. An erasure request under an operator's hold is queued, not refused ----------------------------------------------------
CREATE OR REPLACE FUNCTION consentvault.erasure_request_guard() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    h uuid;
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.erasure_request is a record: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF TG_OP OPERATOR(pg_catalog.=) 'INSERT' THEN
        -- the client's own hold refuses the request by name; an operator's hold queues it (the caller marks it held)
        SELECT lh.hold_id INTO h FROM consentvault.legal_hold lh
         WHERE lh.org_id = NEW.org_id AND lh.released_at IS NULL AND lh.set_by_kind = 'member'
           AND (lh.scope = 'org' OR NEW.contact_fp = ANY (lh.contact_fps))
         ORDER BY lh.set_at, lh.hold_id LIMIT 1;
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

-- 4. An emergency access without a notice exists only under a gag ----------------------------------------------------------
ALTER TABLE consentvault.operator_access DROP CONSTRAINT operator_access_basis;
ALTER TABLE consentvault.operator_access ADD CONSTRAINT operator_access_basis CHECK (
    (approved_by_client IS NOT NULL AND NOT emergency)
    OR (approved_by_client IS NULL AND emergency AND (client_notified_at IS NOT NULL OR legal_process_id IS NOT NULL)));

CREATE FUNCTION consentvault.operator_access_gag() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.emergency AND NEW.client_notified_at IS NULL AND NOT EXISTS (
        SELECT 1 FROM consentvault.legal_process p
         WHERE p.org_id = NEW.org_id AND p.process_id = NEW.legal_process_id AND p.notice_prohibited_basis IS NOT NULL
           AND p.client_notified_at IS NULL) THEN
        RAISE EXCEPTION 'consentvault.operator_access: an emergency access notifies the customer unless its legal process prohibits notice'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER operator_access_gag BEFORE INSERT ON consentvault.operator_access
    FOR EACH ROW EXECUTE FUNCTION consentvault.operator_access_gag();
