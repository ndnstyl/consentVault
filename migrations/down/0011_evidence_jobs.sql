-- Reverses 0011_evidence_jobs.sql: background jobs dispatch the live statuses only again, and the unbind goes.
-- Run it as a superuser (or a BYPASSRLS role), in one transaction.
BEGIN;

DO $$
BEGIN
    IF to_regprocedure('consentvault.evidence_org_ids()') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0011 refused: consentvault.evidence_org_ids() is missing; 0011 is not applied';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION consentvault.dispatch_orgs(p_job text) RETURNS TABLE (org_id uuid, token text)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    o uuid;
BEGIN
    IF p_job IS NULL OR p_job !~ '^[a-z][a-z0-9_]{0,40}$' THEN
        RAISE EXCEPTION 'consentvault dispatch: job name must match ^[a-z][a-z0-9_]{0,40}$'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR o IN SELECT * FROM consentvault.active_org_ids() LOOP
        org_id := o;
        token := consentvault.sign_org_token(o, ARRAY['worker:' || p_job], NULL, 300);
        RETURN NEXT;
    END LOOP;
END;
$$;
DROP FUNCTION consentvault.evidence_org_ids();
DROP FUNCTION consentvault.sync_system_unbind_credential(uuid);

COMMIT;
