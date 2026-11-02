-- Reverses 0040_price_change_mark.sql. Run it as the schema owner (or a superuser or a role that can act as it), in one
-- transaction; it refuses any other role. Run down/0041_price_set_mark.sql first if that is applied. The price-change marks go with
-- their columns; billing_link_account and usage_plan_of_record return as 0007 and 0027 shipped them.
BEGIN;

DO $$
DECLARE
    owner_name text := (SELECT pg_get_userbyid(n.nspowner) FROM pg_namespace n WHERE n.nspname = 'consentvault');
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'consentvault'
                    AND table_name = 'billing_account' AND column_name = 'price_changed_at') THEN
        RAISE EXCEPTION 'consentvault down 0040 refused: 0040 is not applied';
    END IF;
    IF to_regprocedure('consentvault.billing_link_account(uuid,text,text,text,text,text,text,bigint,bigint,timestamptz,timestamptz,text)') IS NOT NULL THEN
        RAISE EXCEPTION 'consentvault down 0040 refused: 0041 is still applied; run down/0041_price_set_mark.sql first';
    END IF;
    -- the functions recreated below must belong to the schema owner, so only the owner, a role that can act as it, or a
    -- superuser may run this file, and it acts as the owner for the rest of the transaction
    IF NOT (SELECT rolsuper OR pg_has_role(current_user, owner_name, 'MEMBER') FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'consentvault down 0040 refused: run it as the schema owner (%) or a role that can act as it', owner_name;
    END IF;
    EXECUTE format('SET LOCAL ROLE %I', owner_name);
END
$$;

DROP FUNCTION consentvault.usage_plan_of_record();
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

CREATE OR REPLACE FUNCTION consentvault.billing_link_account(
    p_org uuid, p_customer text, p_subscription text, p_price text, p_status text, p_plan_id text, p_plan_name text,
    p_included_events bigint, p_included_gate_checks bigint, p_period_start timestamptz, p_period_end timestamptz)
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
                plan_id, plan_name, included_events, included_gate_checks, period_start, period_end)
            VALUES (p_org, p_customer, p_subscription, p_price, p_status, p_plan_id, p_plan_name, p_included_events,
                    p_included_gate_checks, p_period_start, p_period_end);
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
            updated_at = now()
          WHERE org_id = p_org;
    END IF;
    PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.billing_link_account(uuid, text, text, text, text, text, text, bigint, bigint,
    timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_link_account(uuid, text, text, text, text, text, text, bigint, bigint,
    timestamptz, timestamptz) TO consentvault_app;

ALTER TABLE consentvault.billing_account DROP COLUMN prev_period_start;
ALTER TABLE consentvault.billing_account DROP COLUMN price_changed_at;

COMMIT;
