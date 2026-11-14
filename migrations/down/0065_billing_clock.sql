-- Undo 0065: the billing reads return to the form that took their caller's time.

DROP FUNCTION consentvault.usage_retry_due();
CREATE FUNCTION consentvault.usage_retry_due(p_at timestamptz)
    RETURNS TABLE (day date, events bigint, gate_checks bigint, stripe_ack jsonb)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    RETURN QUERY
    SELECT u.day, u.events, u.gate_checks, u.stripe_ack
      FROM consentvault.usage_day u
     WHERE u.org_id = org AND u.reported_at IS NULL AND u.retry_at IS NOT NULL AND u.retry_at <= p_at
     ORDER BY u.day;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_retry_due(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_retry_due(timestamptz) TO consentvault_app, consentvault_worker;

DROP FUNCTION consentvault.usage_run_age();
CREATE FUNCTION consentvault.usage_run_age(p_at timestamptz) RETURNS double precision
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT extract(epoch FROM p_at - r.finished_at) FROM consentvault.usage_run r WHERE r.job = 'daily';
$$;
REVOKE ALL ON FUNCTION consentvault.usage_run_age(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_run_age(timestamptz) TO consentvault_worker;
