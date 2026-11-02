-- Reverses 0056_confirmation_send_brand.sql: confirmation_enqueue goes back to its 0049 body and the send rows lose their brand.
BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'consentvault'
                   AND table_name = 'confirmation_send_intent' AND column_name = 'brand_id') THEN
        RAISE EXCEPTION 'consentvault down 0056 refused: 0056 is not applied';
    END IF;
END
$$;

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

ALTER TABLE consentvault.confirmation_send_intent DROP COLUMN brand_id;

COMMIT;
