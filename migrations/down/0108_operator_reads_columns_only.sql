-- Reverses 0108_operator_reads_columns_only.sql: the wider grants and the earlier receipt function are back.
BEGIN;
CREATE OR REPLACE FUNCTION consentvault.receipt_of(p_event_id uuid)
    RETURNS TABLE (seq bigint, row_hash text, received_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT e.chain_seq, e.row_hash, e.received_at FROM consentvault.post_history_all_events e
     WHERE e.event_id = p_event_id
       AND (e.org_id = consentvault.current_org()
            OR (consentvault.current_org() IS NULL AND (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user)))
     ORDER BY (e.seq = e.chain_seq) DESC LIMIT 1;
$$;
CREATE OR REPLACE FUNCTION consentvault.health_counts()
    RETURNS TABLE (unsealed_over_1h bigint, first_event_at timestamptz, first_event_sealed boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT (SELECT count(*) FROM consentvault.post_history_all_events e
             WHERE e.org_id = (SELECT consentvault.current_org()) AND e.received_at < clock_timestamp() - interval '1 hour'
               AND NOT EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.org_id = e.org_id AND s.event_id = e.event_id)
               AND NOT EXISTS (SELECT 1 FROM consentvault.post_history_seal h JOIN consentvault.post_history p
                                ON p.org_id = h.org_id AND p.history_seq = h.history_seq WHERE p.org_id = e.org_id AND p.event_id = e.event_id)),
           f.received_at,
           CASE WHEN f.event_id IS NULL THEN NULL
                ELSE EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.org_id = f.org_id AND s.event_id = f.event_id)
                  OR EXISTS (SELECT 1 FROM consentvault.post_history_seal h JOIN consentvault.post_history p
                              ON p.org_id = h.org_id AND p.history_seq = h.history_seq WHERE p.org_id = f.org_id AND p.event_id = f.event_id) END
    FROM (SELECT 1) one
    LEFT JOIN LATERAL (SELECT e.org_id, e.event_id, e.received_at FROM consentvault.post_history_all_events e
                        WHERE e.org_id = (SELECT consentvault.current_org()) ORDER BY e.seq LIMIT 1) f ON true;
$$;
CREATE OR REPLACE FUNCTION consentvault.source_last_events()
    RETURNS TABLE (source_id uuid, last_event_at timestamptz, last_event_seq bigint, last_event_sealed boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT DISTINCT ON (e.source_id) e.source_id, e.received_at, e.seq,
           EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.org_id = e.org_id AND s.event_id = e.event_id)
             OR EXISTS (SELECT 1 FROM consentvault.post_history_seal h JOIN consentvault.post_history p
                         ON p.org_id = h.org_id AND p.history_seq = h.history_seq WHERE p.org_id = e.org_id AND p.event_id = e.event_id)
    FROM consentvault.post_history_all_events e
    WHERE e.org_id = (SELECT consentvault.current_org()) AND e.source_id IS NOT NULL
    ORDER BY e.source_id, e.seq DESC;
$$;
DROP VIEW consentvault.post_history_event_index;
DROP VIEW consentvault.post_history_receipts;
GRANT SELECT ON consentvault.outbox, consentvault.confirmation_send_intent, consentvault.event, consentvault.post_history,
    consentvault.post_history_all_events, consentvault.history_events, consentvault.event_source_post, consentvault.history_stop_lift,
    consentvault.post_history_seal, consentvault.connected_system, consentvault.contact_key, consentvault.effect_intent TO consentvault_operator;
GRANT SELECT, INSERT ON consentvault.effect_watermark TO consentvault_operator;
COMMIT;
