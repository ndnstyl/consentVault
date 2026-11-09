-- Pure projection: the operator role reads only the columns its owned functions use. Earlier migrations of this lane gave it whole-table reads
-- (the seed, the receipt, the history stop reader, the push material); this takes them back and grants columns instead. The push material
-- function needs no row security bypass (it reads the entered organisation) and is the schema owner's again.
REVOKE SELECT ON consentvault.outbox, consentvault.confirmation_send_intent, consentvault.event, consentvault.post_history,
    consentvault.post_history_all_events, consentvault.history_events, consentvault.raw_post, consentvault.raw_post_original_arrival,
    consentvault.event_source_post, consentvault.history_stop_lift, consentvault.post_history_seal, consentvault.connected_system,
    consentvault.contact_key, consentvault.effect_intent, consentvault.effect_watermark FROM consentvault_operator;
REVOKE INSERT ON consentvault.effect_watermark FROM consentvault_operator;
GRANT SELECT (org_id, outbox_id, system_id, contact_fp, channel, status) ON consentvault.outbox TO consentvault_operator;
GRANT SELECT (org_id, send_id, contact_fp, channel, status) ON consentvault.confirmation_send_intent TO consentvault_operator;
GRANT SELECT (org_id) ON consentvault.effect_watermark TO consentvault_operator;
GRANT SELECT (org_id, event_id, seq, row_hash, received_at, source_id) ON consentvault.event TO consentvault_operator;
GRANT SELECT (org_id, event_id, post_id, history_seq, row_hash, received_at, contact_fp, event_type_sent, standing, earliest_copy,
              channels_sent, origin_sent, method_sent) ON consentvault.post_history TO consentvault_operator;
GRANT SELECT (org_id, stop_event_id) ON consentvault.history_stop_lift TO consentvault_operator;
GRANT SELECT (org_id, history_seq) ON consentvault.post_history_seal TO consentvault_operator;
GRANT SELECT (source_id_sent, label) ON consentvault.post_history TO consentvault_operator;
GRANT SELECT (org_id, post_id, role) ON consentvault.event_source_post TO consentvault_operator;
GRANT SELECT (org_id, post_id, received_at, body_sha256) ON consentvault.raw_post TO consentvault_operator;
GRANT SELECT (org_id, post_id, arrived_at) ON consentvault.raw_post_original_arrival TO consentvault_operator;
-- revoking a whole table also took the columns the operator held before (migration 0060): they are given back
GRANT SELECT (org_id, system_id, status, connector) ON consentvault.connected_system TO consentvault_operator;

DO $$
BEGIN
    EXECUTE pg_catalog.format('ALTER FUNCTION consentvault.effect_legacy_push_material(uuid) OWNER TO %s',
                              (SELECT n.nspowner::pg_catalog.regrole FROM pg_catalog.pg_namespace n WHERE n.nspname OPERATOR(pg_catalog.=) 'consentvault'));
END
$$;

-- The receipt reads a view of five columns of the event and the history row, so the operator needs those and nothing more.
CREATE VIEW consentvault.post_history_receipts WITH (security_invoker = true) AS
SELECT e.org_id, e.event_id, e.seq AS chain_seq, e.row_hash, e.received_at, true AS frozen FROM consentvault.event e
UNION ALL
SELECT h.org_id, h.event_id, h.history_seq, h.row_hash, h.received_at, false FROM consentvault.post_history h;
GRANT SELECT (org_id, event_id, chain_seq, row_hash, received_at, frozen) ON consentvault.post_history_receipts TO consentvault_operator;

CREATE OR REPLACE FUNCTION consentvault.receipt_of(p_event_id uuid)
    RETURNS TABLE (seq bigint, row_hash text, received_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT e.chain_seq, e.row_hash, e.received_at FROM consentvault.post_history_receipts e
     WHERE e.event_id = p_event_id
       AND (e.org_id = consentvault.current_org()
            OR (consentvault.current_org() IS NULL AND (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user)))
     ORDER BY e.frozen DESC LIMIT 1;
$$;

-- The health counts and the last event of each source (owned by the operator role since migration 0005) read a view of the five columns they
-- need: every event, and the history rows of the posts that came after an organisation's cutover.
CREATE VIEW consentvault.post_history_event_index WITH (security_invoker = true) AS
SELECT e.org_id, e.event_id, e.seq, e.received_at, e.source_id FROM consentvault.event e
UNION ALL
SELECT h.org_id, h.event_id, coalesce((SELECT max(f.seq) FROM consentvault.event f WHERE f.org_id = h.org_id), 0) + h.history_seq,
       h.received_at, NULLIF(h.source_id_sent, '')::uuid
  FROM consentvault.post_history h
 WHERE h.label = 'projected' AND h.standing = 'counts' AND h.earliest_copy AND h.event_type_sent IS NOT NULL
   AND EXISTS (SELECT 1 FROM consentvault.effect_watermark w WHERE w.org_id = h.org_id)
   AND NOT EXISTS (SELECT 1 FROM consentvault.event_source_post s WHERE s.org_id = h.org_id AND s.post_id = h.post_id AND s.role = 'trigger');
GRANT SELECT (org_id, event_id, seq, received_at, source_id) ON consentvault.post_history_event_index TO consentvault_operator;

CREATE OR REPLACE FUNCTION consentvault.health_counts()
    RETURNS TABLE (unsealed_over_1h bigint, first_event_at timestamptz, first_event_sealed boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT (SELECT count(*) FROM consentvault.post_history_event_index e
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
    LEFT JOIN LATERAL (SELECT e.org_id, e.event_id, e.received_at FROM consentvault.post_history_event_index e
                        WHERE e.org_id = (SELECT consentvault.current_org()) ORDER BY e.seq LIMIT 1) f ON true;
$$;

CREATE OR REPLACE FUNCTION consentvault.source_last_events()
    RETURNS TABLE (source_id uuid, last_event_at timestamptz, last_event_seq bigint, last_event_sealed boolean)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT DISTINCT ON (e.source_id) e.source_id, e.received_at, e.seq,
           EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.org_id = e.org_id AND s.event_id = e.event_id)
             OR EXISTS (SELECT 1 FROM consentvault.post_history_seal h JOIN consentvault.post_history p
                         ON p.org_id = h.org_id AND p.history_seq = h.history_seq WHERE p.org_id = e.org_id AND p.event_id = e.event_id)
    FROM consentvault.post_history_event_index e
    WHERE e.org_id = (SELECT consentvault.current_org()) AND e.source_id IS NOT NULL
    ORDER BY e.source_id, e.seq DESC;
$$;
