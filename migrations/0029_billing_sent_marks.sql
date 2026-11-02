-- Usage reporting: a sent mark written before each Stripe meter call, and the subscription the vault holds for an
-- organisation, readable by the webhook before a different one replaces it.
--
-- usage_day.stripe_sent: meter -> the time the job first claimed the send. A send whose confirmation was never saved is
-- told apart from a send never attempted; Stripe's meter-event dedupe window is about 24 hours, so past that window the
-- job alarms instead of sending the same identifier again.
-- usage_claim_send(day, meter): writes the mark when none exists (returns NULL) or returns the earlier mark's age in seconds.
-- billing_held_subscription(org): the subscription id and status the vault holds, so a webhook can name a second live one.

ALTER TABLE consentvault.usage_day ADD COLUMN stripe_sent jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE FUNCTION consentvault.usage_claim_send(p_day date, p_meter text) RETURNS double precision
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org   uuid := consentvault.usage_require_scope();
    prior timestamptz;
BEGIN
    IF p_meter NOT IN ('events', 'gate_checks') THEN
        RAISE EXCEPTION 'consentvault usage: a meter (events or gate_checks) is required'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT (u.stripe_sent ->> p_meter)::timestamptz INTO prior
      FROM consentvault.usage_day u WHERE u.org_id = org AND u.day = p_day FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault usage: no count recorded for % on %', org, p_day USING ERRCODE = 'no_data_found';
    END IF;
    IF prior IS NOT NULL THEN
        RETURN extract(epoch FROM clock_timestamp() - prior);
    END IF;
    UPDATE consentvault.usage_day u
       SET stripe_sent = u.stripe_sent || jsonb_build_object(p_meter, clock_timestamp())
     WHERE u.org_id = org AND u.day = p_day;
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_claim_send(date, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_claim_send(date, text) TO consentvault_app, consentvault_worker;

CREATE FUNCTION consentvault.billing_held_subscription(p_org uuid)
    RETURNS TABLE (stripe_subscription_id text, status text)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    prev text := pg_catalog.current_setting('consentvault.org_token', true);
BEGIN
    IF p_org IS NULL THEN
        RAISE EXCEPTION 'consentvault billing: an organisation is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_catalog.set_config('consentvault.org_token',
                                  consentvault.sign_org_token(p_org, ARRAY['billing'], NULL, 60), true);
    RETURN QUERY SELECT a.stripe_subscription_id, a.status FROM consentvault.billing_account a WHERE a.org_id = p_org;
    PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.billing_held_subscription(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_held_subscription(uuid) TO consentvault_app;
