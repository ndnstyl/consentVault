-- Company sign-in binding guards. (1) The operator console may run the alarm-clear function, so unbinding a company sign-in
-- answers a lifted-requirement notice instead of leaving it pinned. (2) A sign-in-service organization may be bound to only
-- one ConsentVault organization: this owner-rights function reads across organizations (the newest version of each) and
-- refuses a binding another organization holds. It takes a lock keyed on the sign-in-service organization, held to the end of
-- the caller's transaction, so two organizations binding the same one at the same moment cannot both pass.
GRANT EXECUTE ON FUNCTION consentvault.org_alarm_clear(text) TO consentvault_console;

GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
GRANT SELECT (org_id, version, workos_org_id) ON consentvault.org_sso TO consentvault_operator;
GRANT EXECUTE ON FUNCTION consentvault.current_org() TO consentvault_operator;

CREATE FUNCTION consentvault.sso_binding_check(p_workos_org text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    me uuid := consentvault.current_org();
BEGIN
    IF me IS NULL OR p_workos_org IS NULL THEN
        RAISE EXCEPTION 'consentvault sso: an entered organization and a sign-in-service organization are required'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('consentvault.sso_wos:' || p_workos_org));
    IF EXISTS (SELECT 1 FROM consentvault.org_sso s
                WHERE s.org_id <> me AND s.workos_org_id = p_workos_org
                  AND s.version = (SELECT max(v.version) FROM consentvault.org_sso v WHERE v.org_id = s.org_id)) THEN
        RAISE EXCEPTION 'consentvault sso: that sign-in-service organization is already bound to another organization'
            USING ERRCODE = 'unique_violation';
    END IF;
END;
$$;
ALTER FUNCTION consentvault.sso_binding_check(text) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.sso_binding_check(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sso_binding_check(text) TO consentvault_console;

REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
