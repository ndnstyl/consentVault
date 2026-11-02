-- The price-change mark also watches the overage prices: a subscription whose base price is unchanged but whose metered
-- overage price was swapped is a price change too (Stripe drops late usage for a replaced price either way).
-- billing_account.price_set is every price on the subscription (base and overage ids, sorted, joined by commas);
-- billing_link_account takes it as an optional twelfth argument and sets price_changed_at when it differs.

ALTER TABLE consentvault.billing_account ADD COLUMN price_set text;

DROP FUNCTION consentvault.billing_link_account(uuid, text, text, text, text, text, text, bigint, bigint,
    timestamptz, timestamptz);
CREATE FUNCTION consentvault.billing_link_account(
    p_org uuid, p_customer text, p_subscription text, p_price text, p_status text, p_plan_id text, p_plan_name text,
    p_included_events bigint, p_included_gate_checks bigint, p_period_start timestamptz, p_period_end timestamptz, p_price_set text DEFAULT NULL)
    RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    prev text := pg_catalog.current_setting('consentvault.org_token', true);
    held text;
BEGIN
    IF p_org IS NULL OR p_customer IS NULL THEN
        RAISE EXCEPTION 'consentvault billing: an organisation and a Stripe customer are required'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_catalog.set_config('consentvault.org_token',
                                  consentvault.sign_org_token(p_org, ARRAY['billing'], NULL, 60), true);
    SELECT stripe_customer_id INTO held FROM consentvault.billing_account WHERE org_id = p_org FOR UPDATE;
    IF FOUND AND held <> p_customer THEN
        RAISE EXCEPTION 'consentvault billing: organisation % is already linked to another Stripe customer', p_org
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NOT FOUND THEN
        INSERT INTO consentvault.billing_account (org_id, stripe_customer_id, stripe_subscription_id, price_id, status,
                plan_id, plan_name, included_events, included_gate_checks, period_start, period_end, price_set)
            VALUES (p_org, p_customer, p_subscription, p_price, p_status, p_plan_id, p_plan_name, p_included_events,
                    p_included_gate_checks, p_period_start, p_period_end, p_price_set);
    ELSE
        UPDATE consentvault.billing_account SET
            stripe_subscription_id = coalesce(p_subscription, stripe_subscription_id),
            price_id = coalesce(p_price, price_id),
            status = coalesce(p_status, status),
            plan_id = coalesce(p_plan_id, plan_id),
            plan_name = coalesce(p_plan_name, plan_name),
            included_events = coalesce(p_included_events, included_events),
            included_gate_checks = coalesce(p_included_gate_checks, included_gate_checks),
            period_start = coalesce(p_period_start, period_start),
            period_end = coalesce(p_period_end, period_end),
            price_changed_at = CASE WHEN (p_price IS NOT NULL AND price_id IS NOT NULL AND p_price <> price_id)
                                      OR (p_price_set IS NOT NULL AND price_set IS NOT NULL AND p_price_set <> price_set)
                                    THEN clock_timestamp() ELSE price_changed_at END,
            price_set = coalesce(p_price_set, price_set),
            prev_period_start = CASE WHEN p_period_start IS NOT NULL AND period_start IS NOT NULL
                                          AND p_period_start > period_start
                                     THEN period_start ELSE prev_period_start END,
            updated_at = now()
          WHERE org_id = p_org;
    END IF;
    PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.billing_link_account(uuid, text, text, text, text, text, text, bigint, bigint,
    timestamptz, timestamptz, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_link_account(uuid, text, text, text, text, text, text, bigint, bigint,
    timestamptz, timestamptz, text) TO consentvault_app;
