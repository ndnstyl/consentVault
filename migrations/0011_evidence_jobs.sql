-- Evidence and suppression jobs never pause for non-payment (ruled 2026-10-29). A stop that does not reach a client's
-- connected systems harms the consumer, and evidence is never paused, so the background jobs (sync, anchor, seal,
-- reconcile, ...) run for every organisation that is not closed: trial, active, past_due, suspended and offboarding.
-- Offboarding leaves these jobs once its final export is taken (the offboarding lane narrows this list then). The
-- billing usage job alone keeps the live statuses (active_org_ids): a suspended organisation is not metered.
-- Also adds the sync lane's unbind of a system's signal credential.

GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;

CREATE FUNCTION consentvault.evidence_org_ids() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT org_id FROM consentvault.organization WHERE status <> 'closed' ORDER BY org_id;
$$;
ALTER FUNCTION consentvault.evidence_org_ids() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.evidence_org_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.evidence_org_ids() TO CURRENT_USER;

REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;

CREATE OR REPLACE FUNCTION consentvault.dispatch_orgs(p_job text) RETURNS TABLE (org_id uuid, token text)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    o uuid;
BEGIN
    IF p_job IS NULL OR p_job !~ '^[a-z][a-z0-9_]{0,40}$' THEN
        RAISE EXCEPTION 'consentvault dispatch: job name must match ^[a-z][a-z0-9_]{0,40}$'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_job = 'usage' THEN
        FOR o IN SELECT * FROM consentvault.active_org_ids() LOOP
            org_id := o;
            token := consentvault.sign_org_token(o, ARRAY['worker:' || p_job], NULL, 300);
            RETURN NEXT;
        END LOOP;
    ELSE
        FOR o IN SELECT * FROM consentvault.evidence_org_ids() LOOP
            org_id := o;
            token := consentvault.sign_org_token(o, ARRAY['worker:' || p_job], NULL, 300);
            RETURN NEXT;
        END LOOP;
    END IF;
END;
$$;

-- Unbind: the system carries no signal credential any more (signals on the old credential answer role_not_allowed).
CREATE FUNCTION consentvault.sync_system_unbind_credential(p_system_id uuid) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'developer']);
    was uuid;
BEGIN
    SELECT s.signal_credential_id INTO was FROM consentvault.connected_system s
     WHERE s.org_id = org AND s.system_id = p_system_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault sync: system % is not in the current organisation', p_system_id
            USING ERRCODE = 'no_data_found';
    END IF;
    UPDATE consentvault.connected_system s SET signal_credential_id = NULL
     WHERE s.org_id = org AND s.system_id = p_system_id;
    RETURN was;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_system_unbind_credential(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_system_unbind_credential(uuid) TO consentvault_app;
