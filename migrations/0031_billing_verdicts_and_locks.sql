-- Usage reporting verdicts and checkout serialisation.
--
-- usage_day.stripe_verdict: key -> {at, acknowledged, by, acknowledged_at}. A day that cannot be reported
-- ("abandoned" before the period start, "unconfirmed:<meter>" sent with no saved confirmation, "failed:<meter>" refused)
-- is recorded once: the job alarms the first time and stays red until an operator acknowledges it.
-- usage_day.retry_at: when a refused or unreachable send is next due; the retry pass reads it.
-- billing_lock_account(org): the organisation's billing row locked FOR UPDATE until the caller's transaction ends, so two
-- checkout pages for one customer are made one after the other.

ALTER TABLE consentvault.usage_day ADD COLUMN stripe_verdict jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE consentvault.usage_day ADD COLUMN retry_at timestamptz;

CREATE FUNCTION consentvault.usage_clear_send(p_day date, p_meter text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    UPDATE consentvault.usage_day u
       SET stripe_sent = u.stripe_sent - p_meter, retry_at = clock_timestamp() + interval '1 hour'
     WHERE u.org_id = org AND u.day = p_day AND u.reported_at IS NULL;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_clear_send(date, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_clear_send(date, text) TO consentvault_app, consentvault_worker;

-- 'new' the first time a key is recorded, 'open' while it stands, 'acknowledged' once an operator has cleared it.
CREATE FUNCTION consentvault.usage_note_verdict(p_day date, p_key text) RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org  uuid := consentvault.usage_require_scope();
    cur  jsonb;
    seen boolean;
BEGIN
    IF p_key IS NULL OR length(p_key) NOT BETWEEN 1 AND 60 THEN
        RAISE EXCEPTION 'consentvault usage: a verdict key of 1 to 60 characters is required'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT u.stripe_verdict INTO cur FROM consentvault.usage_day u WHERE u.org_id = org AND u.day = p_day FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault usage: no count recorded for % on %', org, p_day USING ERRCODE = 'no_data_found';
    END IF;
    seen := cur ? p_key;
    IF NOT seen THEN
        UPDATE consentvault.usage_day u
           SET stripe_verdict = u.stripe_verdict || jsonb_build_object(p_key,
                 jsonb_build_object('at', clock_timestamp(), 'acknowledged', false))
         WHERE u.org_id = org AND u.day = p_day;
        RETURN 'new';
    END IF;
    RETURN CASE WHEN (cur -> p_key ->> 'acknowledged')::boolean THEN 'acknowledged' ELSE 'open' END;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_note_verdict(date, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_note_verdict(date, text) TO consentvault_app, consentvault_worker;

-- A verdict that resolved itself (a refused send that later succeeded) leaves the row.
CREATE FUNCTION consentvault.usage_clear_verdict(p_day date, p_key text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    UPDATE consentvault.usage_day u SET stripe_verdict = u.stripe_verdict - p_key
     WHERE u.org_id = org AND u.day = p_day AND u.stripe_verdict ? p_key;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_clear_verdict(date, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_clear_verdict(date, text) TO consentvault_app, consentvault_worker;

CREATE FUNCTION consentvault.usage_acknowledge(p_day date, p_key text, p_by text) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.usage_require_scope();
BEGIN
    IF p_by IS NULL OR length(p_by) NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'consentvault usage: an acknowledgement names who made it' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE consentvault.usage_day u
       SET stripe_verdict = jsonb_set(u.stripe_verdict, ARRAY[p_key],
             (u.stripe_verdict -> p_key) || jsonb_build_object('acknowledged', true, 'by', p_by,
                                                               'acknowledged_at', clock_timestamp()))
     WHERE u.org_id = org AND u.day = p_day AND u.stripe_verdict ? p_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault usage: no verdict % on % for %', p_key, p_day, org USING ERRCODE = 'no_data_found';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.usage_acknowledge(date, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.usage_acknowledge(date, text, text) TO consentvault_app, consentvault_worker;

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

CREATE FUNCTION consentvault.billing_lock_account(p_org uuid) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    held uuid;
BEGIN
    IF p_org IS NULL OR p_org IS DISTINCT FROM consentvault.current_org() THEN
        RAISE EXCEPTION 'consentvault billing: the lock is taken for the entered organisation only'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT a.org_id INTO held FROM consentvault.billing_account a WHERE a.org_id = p_org FOR UPDATE;
    RETURN FOUND;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.billing_lock_account(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_lock_account(uuid) TO consentvault_app;

-- Whether the organisation already has this alarm open (raised and not acknowledged): a repeat is not raised again.
CREATE FUNCTION consentvault.billing_alarm_open(p_org uuid, p_name text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM consentvault.operator_alarm a
                    WHERE a.org_id = p_org AND a.name = p_name AND a.acknowledged_at IS NULL);
$$;
REVOKE ALL ON FUNCTION consentvault.billing_alarm_open(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.billing_alarm_open(uuid, text) TO consentvault_app;
