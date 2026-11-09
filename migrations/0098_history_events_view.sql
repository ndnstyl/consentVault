-- Pure projection, readers: the counted, first-copy history rows that no event of the frozen table stands beside, in the columns a reader of
-- events expects (the proof's timeline, the evidence bundle, the records layer). An invoker view: row security and the evidence read scope
-- bind the caller as they bind a direct read of the history. ``seq`` is the history sequence number; ``arrival_at`` is the row's place.
CREATE VIEW consentvault.history_events WITH (security_invoker = true) AS
SELECT h.org_id, h.history_seq AS seq, h.event_id, h.post_id, h.event_type_sent AS event_type, h.channels_sent AS channels,
       h.purposes_sent AS purposes, NULLIF(h.source_id_sent, '')::uuid AS source_id,
       (SELECT array_agg(b::uuid) FROM unnest(h.brand_ids_sent) b) AS brand_ids, h.wording_sha256_sent AS disclosure_sha256,
       h.contact_fp, NULL::text AS subject_fp, h.contact_kind_sent AS contact_kind, h.origin_sent AS origin, h.method_sent AS method,
       h.received_at, h.placed_at AS arrival_at, h.contact_ct, h.row_hash, h.prev_hash, h.label
  FROM consentvault.post_history h
 WHERE h.label = 'projected' AND h.standing = 'counts' AND h.earliest_copy AND h.event_type_sent IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM consentvault.event_source_post s
                    WHERE s.org_id = h.org_id AND s.post_id = h.post_id AND s.role = 'trigger');
GRANT SELECT ON consentvault.history_events TO consentvault_app, consentvault_worker, consentvault_console, consentvault_integrity;
