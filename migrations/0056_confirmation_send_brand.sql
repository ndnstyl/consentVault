-- A send row names the brand it was sent as (confirmations.md section 5, amended 2026-10-31). The brand is the rule's
-- sending_brand_id at the moment the intent is made, copied onto the intent, so a later change of the rule never rewrites what an
-- old send was sent as. Reply sends (opt-out, HELP, START) answer a reply and have no source, so their brand stays null; so do
-- intents made before this migration. The column is not a sealed column of any table a seal covers.
ALTER TABLE consentvault.confirmation_send_intent ADD COLUMN brand_id uuid;

CREATE OR REPLACE FUNCTION consentvault.confirmation_enqueue(p_event_id uuid, p_contact_fp text) RETURNS integer
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
    INSERT INTO consentvault.confirmation_send_intent (org_id, send_id, basis_event_id, source_id, brand_id, contact_fp, channel,
                                                       status, created_at, at)
    SELECT org, gen_random_uuid(), p_event_id, ev.sid, r.sending_brand_id, p_contact_fp, r.channel, 'intent', clock_timestamp(),
           clock_timestamp()
      FROM consentvault.confirmation_rule r
     WHERE r.org_id = org AND r.source_id = ev.sid AND r.enabled
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$$;
