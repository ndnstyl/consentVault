-- The alarms a customer's admins and compliance viewers read on GET /v1/health (admin.md, "which alarms a customer sees"). Two of
-- them are derived from records the runtime role cannot read directly, so one definer function reads exactly those, for the
-- entered organization only, and returns names, a count and a time:
--   restore.stops_unconfirmed       admin and compliance viewer: stops a restore put back without their confirmation that
--                                   still stand (no later grant or release for the person, no confirmed stop for the entry)
--   billing.second_live_subscription  admin only: the open billing alarm (it clears through the billing webhook)
-- A usage_* alarm is never returned here: those stay with the operator.
CREATE FUNCTION consentvault.customer_alarm_rows(p_admin boolean)
    RETURNS TABLE (name text, since timestamptz, count integer)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'audit_read', 'proof_read']);
BEGIN
    IF p_admin AND NOT coalesce(consentvault.current_token_scopes() && ARRAY['admin'], false) THEN
        RAISE EXCEPTION 'consentvault: the admin alarms need the admin scope' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN QUERY
    SELECT 'restore.stops_unconfirmed'::text, min(e.received_at), count(*)::integer
      FROM consentvault.event e
     WHERE e.org_id = org AND e.source = 'erasure' AND e.recorded_by LIKE 'erasure-unconfirmed:%'
       AND NOT EXISTS (SELECT 1 FROM consentvault.event g WHERE g.org_id = org AND g.contact_fp = e.contact_fp
                          AND g.seq > e.seq AND g.event_type IN ('grant', 'release'))
       AND NOT EXISTS (SELECT 1 FROM consentvault.event c WHERE c.org_id = org AND c.source = 'erasure'
                          AND c.recorded_by = 'erasure:' || substr(e.recorded_by, length('erasure-unconfirmed:') + 1))
    HAVING count(*) > 0;
    IF p_admin THEN
        RETURN QUERY
        SELECT a.name::text, min(a.raised_at), NULL::integer FROM consentvault.operator_alarm a
         WHERE a.org_id = org AND a.name = 'billing.second_live_subscription' AND a.acknowledged_at IS NULL
         GROUP BY a.name;
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.customer_alarm_rows(boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.customer_alarm_rows(boolean) TO consentvault_app;
