-- Per-organisation dispatch for long jobs (the sync worker). dispatch_orgs mints every organisation's 300 second token
-- at the start of a run, so one slow organisation could outlive the next one's token. Here the worker lists the
-- organisations first and mints each token just before it drains that organisation. Same organisation set per job as
-- dispatch_orgs (0011): usage meters the live statuses, every other job covers every organisation that is not closed.

CREATE FUNCTION consentvault.dispatch_org_ids(p_job text) RETURNS SETOF uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_job IS NULL OR p_job !~ '^[a-z][a-z0-9_]{0,40}$' THEN
        RAISE EXCEPTION 'consentvault dispatch: job name must match ^[a-z][a-z0-9_]{0,40}$'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_job = 'usage' THEN
        RETURN QUERY SELECT * FROM consentvault.active_org_ids();
    ELSE
        RETURN QUERY SELECT * FROM consentvault.evidence_org_ids();
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.dispatch_org_ids(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.dispatch_org_ids(text) TO consentvault_worker;

CREATE FUNCTION consentvault.dispatch_org_token(p_job text, p_org uuid) RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM consentvault.dispatch_org_ids(p_job) d WHERE d = p_org) THEN
        RAISE EXCEPTION 'consentvault dispatch: organisation % is not dispatched for job %', p_org, p_job
            USING ERRCODE = 'no_data_found';
    END IF;
    RETURN consentvault.sign_org_token(p_org, ARRAY['worker:' || p_job], NULL, 300);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.dispatch_org_token(text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.dispatch_org_token(text, uuid) TO consentvault_worker;

-- A push the worker could not even prepare (the contact's key, the payload or the system's sealed credential would not
-- open) counts as an attempt with error class prepare_failed: retried with backoff and dead when the window ends, so it
-- can never loop unseen.
ALTER TABLE consentvault.outbox DROP CONSTRAINT outbox_last_error_class_check;
ALTER TABLE consentvault.outbox ADD CONSTRAINT outbox_last_error_class_check
    CHECK (last_error_class IN ('timeout', 'http_4xx', 'http_5xx', 'signature_rejected', 'unreachable', 'prepare_failed'));
ALTER TABLE consentvault.delivery DROP CONSTRAINT delivery_error_class_check;
ALTER TABLE consentvault.delivery ADD CONSTRAINT delivery_error_class_check
    CHECK (error_class IN ('timeout', 'http_4xx', 'http_5xx', 'signature_rejected', 'unreachable', 'prepare_failed'));
