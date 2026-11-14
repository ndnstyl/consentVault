-- Confirmation messages, the owner-rights functions (confirmations.md sections 5, 9, 10 and 13).
--
-- * confirmation_enqueue: the grant's own transaction inserts one send intent per enabled rule of its source (core change R1).
-- * confirmation_inbound_lookup, confirmation_host_lookup, confirmation_org_ids, confirmation_work_orgs: the cross-organization
--   reads the sender, the inbound door and the public pages start from. Owned by the operator role, which reads only the columns
--   granted to it in 0047. They answer organization and account ids, never a secret or a message.
-- * confirmation_account_secrets, confirmation_wrapped_secret: the one door to the sealed provider credentials and the wrapped
--   organization secrets, checked against the token's scope.
-- * confirmation_alarm_raise, confirmation_alarm_clear: the only writers of the confirmation alarms in org_alarm.
-- * confirmation_system_source: the system sources "Confirmation replies" and "Email stop page" every stop and START is filed under.
-- Confirmations are free (Mike's ruling, confirmations.md section 10): usage_events_for_day is NOT changed, so a message the
-- provider accepted adds nothing to the metered events. It is recorded as one contact-log row (a recorded event in the proof),
-- never as a billable one.

CREATE FUNCTION consentvault.confirmation_enqueue(p_event_id uuid, p_contact_fp text) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
    ev  record;
    n   integer;
BEGIN
    SELECT e.event_type AS etype, e.source_id AS sid, e.contact_fp AS fp INTO ev
      FROM consentvault.event e WHERE e.org_id = org AND e.event_id = p_event_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault confirmations: event % is not in the current organisation', p_event_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF ev.fp IS DISTINCT FROM p_contact_fp THEN
        RAISE EXCEPTION 'consentvault confirmations: event % is not for that contact fingerprint', p_event_id
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF ev.etype <> 'grant' OR ev.sid IS NULL THEN
        RETURN 0;
    END IF;
    INSERT INTO consentvault.confirmation_send_intent (org_id, send_id, basis_event_id, source_id, contact_fp, channel, status,
                                                       created_at, at)
    SELECT org, gen_random_uuid(), p_event_id, ev.sid, p_contact_fp, r.channel, 'intent', clock_timestamp(), clock_timestamp()
      FROM consentvault.confirmation_rule r
     WHERE r.org_id = org AND r.source_id = ev.sid AND r.enabled
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_enqueue(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_enqueue(uuid, text) TO consentvault_app;

GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;

CREATE FUNCTION consentvault.confirmation_inbound_lookup(p_key text) RETURNS TABLE (org_id uuid, account_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT a.org_id, a.account_id FROM consentvault.sending_account a WHERE a.inbound_key = p_key;
$$;
ALTER FUNCTION consentvault.confirmation_inbound_lookup(text) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.confirmation_inbound_lookup(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_inbound_lookup(text) TO consentvault_app;

CREATE FUNCTION consentvault.confirmation_host_lookup(p_host text) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT h.org_id FROM consentvault.confirmation_link_host h WHERE h.host = lower(p_host) AND h.status IN ('verified', 'failing');
$$;
ALTER FUNCTION consentvault.confirmation_host_lookup(text) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.confirmation_host_lookup(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_host_lookup(text) TO consentvault_app;

CREATE FUNCTION consentvault.confirmation_org_ids() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT org_id FROM consentvault.organization ORDER BY org_id;
$$;
ALTER FUNCTION consentvault.confirmation_org_ids() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.confirmation_org_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_org_ids() TO consentvault_app;

CREATE FUNCTION consentvault.confirmation_work_orgs() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT DISTINCT i.org_id FROM consentvault.confirmation_send_intent i WHERE i.status = 'intent' ORDER BY i.org_id;
$$;
ALTER FUNCTION consentvault.confirmation_work_orgs() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.confirmation_work_orgs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_work_orgs() TO consentvault_app;

REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;

CREATE FUNCTION consentvault.confirmation_account_secrets(p_account uuid)
    RETURNS TABLE (credentials_ct bytea, credential_ids_ct bytea, auth_token_ct bytea)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'developer', 'worker:confirmations']);
BEGIN
    RETURN QUERY SELECT a.credentials_ct, a.credential_ids_ct, a.auth_token_ct FROM consentvault.sending_account a
                  WHERE a.org_id = org AND a.account_id = p_account;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_account_secrets(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_account_secrets(uuid) TO consentvault_app;

CREATE FUNCTION consentvault.confirmation_wrapped_secret(p_kind text) RETURNS bytea
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:confirmations']);
    w   bytea;
BEGIN
    IF p_kind = 'fingerprint' THEN
        SELECT f.wrapped INTO w FROM consentvault.org_fingerprint_secret f WHERE f.org_id = org;
    ELSIF p_kind = 'display' THEN
        SELECT d.wrapped INTO w FROM consentvault.org_display_key d WHERE d.org_id = org;
    ELSE
        RAISE EXCEPTION 'consentvault confirmations: the secret kind is fingerprint or display' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN w;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_wrapped_secret(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_wrapped_secret(text) TO consentvault_app;

-- The one fact about records the sender and the inbound door need: the active record of a contact fingerprint. They hold no
-- read scope on the record list (names and masks open only to a portal session), so this owner-rights function answers just the id.
CREATE FUNCTION consentvault.confirmation_record_of(p_contact_fp text) RETURNS uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:confirmations']);
    rid uuid;
BEGIN
    SELECT r.record_id INTO rid FROM consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND r.erased_at IS NULL ORDER BY r.first_seq DESC LIMIT 1;
    RETURN rid;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_record_of(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_record_of(text) TO consentvault_app;

CREATE FUNCTION consentvault.confirmation_alarm_raise(p_kind text, p_detail jsonb, p_at timestamptz) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:confirmations', 'admin', 'developer']);
    id  uuid;
BEGIN
    IF p_kind IS NULL OR p_kind <> ALL (ARRAY['inbound_signature_failures', 'replies_unread_24h', 'delivery_reports_stale',
            'link_host_failing', 'optout_reply_dead', 'provider_refusal_stop', 'sending_account_failing', 'send_cap_reached',
            'send_outcome_unknown']) THEN
        RAISE EXCEPTION 'consentvault confirmations: % is not a confirmation alarm', p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT a.alarm_id INTO id FROM consentvault.org_alarm a WHERE a.org_id = org AND a.kind = p_kind AND a.cleared_at IS NULL LIMIT 1;
    IF FOUND THEN
        RETURN id;
    END IF;
    INSERT INTO consentvault.org_alarm (org_id, kind, opened_at, detail)
    VALUES (org, p_kind, coalesce(p_at, clock_timestamp()), coalesce(p_detail, '{}'::jsonb)) RETURNING alarm_id INTO id;
    RETURN id;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_alarm_raise(text, jsonb, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_alarm_raise(text, jsonb, timestamptz) TO consentvault_app;

CREATE FUNCTION consentvault.confirmation_alarm_clear(p_kind text, p_at timestamptz) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:confirmations', 'admin', 'developer']);
    n   integer;
BEGIN
    UPDATE consentvault.org_alarm SET cleared_at = coalesce(p_at, clock_timestamp())
     WHERE org_id = org AND kind = p_kind AND cleared_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_alarm_clear(text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_alarm_clear(text, timestamptz) TO consentvault_app;

CREATE FUNCTION consentvault.confirmation_system_source(p_name text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture_verified', 'worker:confirmations', 'admin']);
    sid uuid;
    k   text;
BEGIN
    IF p_name IS NULL OR p_name <> ALL (ARRAY['Confirmation replies', 'Email stop page']) THEN
        RAISE EXCEPTION 'consentvault confirmations: % is not a confirmation system source', p_name
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO consentvault.capture_source (org_id, kind, brand_ids, name, status)
    VALUES (org, 'system', '{}', p_name, 'active')
    ON CONFLICT (org_id, lower(name)) WHERE name IS NOT NULL DO NOTHING;
    SELECT s.source_id, s.kind INTO sid, k FROM consentvault.capture_source s
     WHERE s.org_id = org AND lower(s.name) = lower(p_name);
    IF k IS DISTINCT FROM 'system' THEN
        RAISE EXCEPTION 'consentvault confirmations: a source named % already exists and is not the system source', p_name
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN sid;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_system_source(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_system_source(text) TO consentvault_app;
