-- Pure projection, cutover: a confirmation derived from a history row. The existing sender works on confirmation_send_intent rows; after
-- cutover that row is made from the history row (it cites it in basis_history_event_id) and carries the effect intent's id as its own, so the
-- two are one intent. The runtime role holds no grant on the table, so a definer inserts it, and a trigger keeps the effect intent's state in
-- step with the send status (intent -> pending, sending -> claimed, sent and delivered -> sent, failed, dead and skipped -> failed:<status>).
CREATE FUNCTION consentvault.confirmation_send_from_history(p_intent uuid, p_history_event uuid, p_source uuid, p_brand uuid,
                                                            p_contact_fp text, p_channel text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_org uuid := consentvault.current_org();
BEGIN
    IF v_org IS NULL OR NOT EXISTS (SELECT 1 FROM consentvault.post_history h WHERE h.org_id OPERATOR(pg_catalog.=) v_org
                                     AND h.event_id OPERATOR(pg_catalog.=) p_history_event AND h.contact_fp OPERATOR(pg_catalog.=) p_contact_fp) THEN
        RAISE EXCEPTION 'consentvault confirmations: the history event is not in the entered organisation for that contact' USING ERRCODE = 'no_data_found';
    END IF;
    INSERT INTO consentvault.confirmation_send_intent (org_id, send_id, basis_history_event_id, source_id, brand_id, contact_fp, channel,
                                                       status, created_at, at)
    VALUES (v_org, p_intent, p_history_event, p_source, p_brand, p_contact_fp, p_channel, 'intent', pg_catalog.clock_timestamp(),
            pg_catalog.clock_timestamp())
    ON CONFLICT DO NOTHING;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_send_from_history(uuid, uuid, uuid, uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_send_from_history(uuid, uuid, uuid, uuid, text, text) TO consentvault_app, consentvault_worker;

CREATE FUNCTION consentvault.confirmation_send_state_to_intent() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE consentvault.effect_intent SET state = CASE NEW.status WHEN 'intent' THEN 'pending' WHEN 'sending' THEN 'claimed'
                                                                  WHEN 'sent' THEN 'sent' WHEN 'delivered' THEN 'sent'
                                                                  ELSE 'failed:' OPERATOR(pg_catalog.||) NEW.status END,
                                          state_at = pg_catalog.clock_timestamp()
     WHERE org_id OPERATOR(pg_catalog.=) NEW.org_id AND intent_id OPERATOR(pg_catalog.=) NEW.send_id AND effect OPERATOR(pg_catalog.=) 'confirmation';
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_send_state_to_intent() FROM PUBLIC;
CREATE TRIGGER confirmation_send_state_to_intent AFTER UPDATE OF status ON consentvault.confirmation_send_intent
    FOR EACH ROW WHEN (NEW.status IS DISTINCT FROM OLD.status) EXECUTE FUNCTION consentvault.confirmation_send_state_to_intent();
