-- The database's clock for the billing reads that decided something: which failed usage sends are due for a retry, and how
-- long ago the daily usage run finished (the missed-run alarm). Both took the billing job's time, so a skewed or chosen clock
-- could send a retry early or hide a stale run. Both now read clock_timestamp() and take no time; the old forms are dropped,
-- so a caller still passing a time is refused (no such function). A migration of its own so the billing suite's schema
-- subset carries it.

DROP FUNCTION consentvault.usage_retry_due(timestamptz);
CREATE FUNCTION consentvault.usage_retry_due()
    RETURNS TABLE (day date, events bigint, gate_checks bigint, stripe_ack jsonb)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    RETURN QUERY
    SELECT u.day, u.events, u.gate_checks, u.stripe_ack
      FROM consentvault.usage_day u
     WHERE u.org_id = org AND u.reported_at IS NULL AND u.retry_at IS NOT NULL AND u.retry_at <= clock_timestamp()
     ORDER BY u.day;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_retry_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_retry_due() TO consentvault_app, consentvault_worker;

DROP FUNCTION consentvault.usage_run_age(timestamptz);
CREATE FUNCTION consentvault.usage_run_age() RETURNS double precision
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT extract(epoch FROM clock_timestamp() - r.finished_at) FROM consentvault.usage_run r WHERE r.job = 'daily';
$$;
REVOKE ALL ON FUNCTION consentvault.usage_run_age() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_run_age() TO consentvault_worker;
