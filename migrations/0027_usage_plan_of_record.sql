-- The daily usage job reads the plan of record the webhook keeps, never a live Stripe read per organisation, and
-- reports the days an incomplete Enterprise contract held back once the contract is complete.
--
-- usage_plan_of_record(): the entered organisation's plan, Stripe ids, subscription status and period start.
-- usage_unreported_days(p_from, p_through): its days in that range that Stripe has not acknowledged for both meters.
-- Both run inside the worker:usage token like every usage function (usage_require_scope).

CREATE FUNCTION consentvault.usage_plan_of_record()
    RETURNS TABLE (plan_id text, stripe_customer_id text, stripe_subscription_id text, subscription_status text,
                   period_start timestamptz)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    RETURN QUERY
    SELECT a.plan_id, a.stripe_customer_id, a.stripe_subscription_id, a.status, a.period_start
      FROM consentvault.billing_account a
     WHERE a.org_id = org;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_plan_of_record() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_plan_of_record() TO consentvault_app, consentvault_worker;

CREATE FUNCTION consentvault.usage_unreported_days(p_from date, p_through date)
    RETURNS TABLE (day date, events bigint, gate_checks bigint, stripe_ack jsonb)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    IF p_from IS NULL OR p_through IS NULL OR p_from > p_through THEN
        RAISE EXCEPTION 'consentvault usage: a day range with from on or before through is required'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN QUERY
    SELECT u.day, u.events, u.gate_checks, u.stripe_ack
      FROM consentvault.usage_day u
     WHERE u.org_id = org AND u.day BETWEEN p_from AND p_through AND u.reported_at IS NULL
     ORDER BY u.day;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_unreported_days(date, date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_unreported_days(date, date) TO consentvault_app, consentvault_worker;
