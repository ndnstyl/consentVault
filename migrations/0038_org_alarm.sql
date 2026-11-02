-- Alarms meant for the customer's own admins and compliance viewers (records.md section 6, confirmations.md): one row per
-- alarm, opened by the feature that noticed it and cleared when it is resolved. The runtime role reads them (GET /v1/health);
-- the features that raise and clear them write through their own definer functions. Rows hold names and counts, never a
-- contact point.
CREATE TABLE consentvault.org_alarm (
    org_id     uuid NOT NULL REFERENCES consentvault.organization (org_id),
    alarm_id   uuid NOT NULL DEFAULT gen_random_uuid(),
    kind       text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]{0,40}(\.[a-z][a-z0-9_]{0,40}){0,2}$'),
    opened_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    cleared_at timestamptz,
    detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (org_id, alarm_id)
);
CREATE INDEX org_alarm_open ON consentvault.org_alarm (org_id, opened_at DESC) WHERE cleared_at IS NULL;
ALTER TABLE consentvault.org_alarm ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.org_alarm FORCE ROW LEVEL SECURITY;
CREATE POLICY org_alarm_tenant ON consentvault.org_alarm USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
GRANT SELECT ON consentvault.org_alarm TO consentvault_app;

-- The operator console may open an alarm for an organization (a break-glass that lifted the SSO requirement tells the
-- organization's admins), and an admin's own action may clear it through this one function.
GRANT SELECT, INSERT ON consentvault.org_alarm TO consentvault_console;
CREATE FUNCTION consentvault.org_alarm_clear(p_kind text) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin']);
    n integer;
BEGIN
    UPDATE consentvault.org_alarm SET cleared_at = clock_timestamp() WHERE org_id = org AND kind = p_kind AND cleared_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.org_alarm_clear(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.org_alarm_clear(text) TO consentvault_app;
