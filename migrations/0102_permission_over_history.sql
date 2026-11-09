-- Pure projection, item 19: the permission view is read over history. Its rows come from one source view that holds every event of the
-- frozen table (ranked as migration 0075 ranked them) and every counted, first-copy history row that no event stands beside (ranked by
-- its place: arrival in microseconds, then the post's sequence number, then its history sequence number). The view itself names no table of
-- the frozen chain, carries the rule set it applies, and is labelled derived by the readers that show it.
CREATE VIEW consentvault.post_history_permission_source WITH (security_invoker = true) AS
SELECT e.org_id, e.contact_kind, e.contact_norm, e.contact_fp, e.event_id, e.event_type, e.channels, e.purposes,
       CASE WHEN e.event_type = 'release'
            THEN (SELECT consentvault.arrival_key(g.org_id, g.event_id, g.seq, g.received_at) FROM consentvault.event g
                   WHERE g.org_id = e.org_id AND g.event_id = e.release_of_event_id)
            ELSE consentvault.arrival_key(e.org_id, e.event_id, e.seq, e.received_at) END AS rk,
       (e.event_type IN ('revoke', 'suppress') AND (e.origin <> 'consumer' OR e.method NOT IN ('keyword', 'checkbox', 'written'))) AS hard_stop,
       (e.event_type = 'release' AND e.origin = 'consumer' AND e.release_outcome = 'released') AS valid_release
  FROM consentvault.event e
UNION ALL
SELECT h.org_id, h.contact_kind, NULL::text, h.contact_fp, h.event_id, h.event_type, h.channels, h.purposes,
       pg_catalog.round(extract(epoch FROM h.arrival_at) * 1000000) * 1e30
         + coalesce((SELECT p.seq FROM consentvault.raw_post p WHERE p.org_id = h.org_id AND p.post_id = h.post_id), 0)::numeric * 1e15
         + h.seq::numeric,
       (h.event_type IN ('revoke', 'suppress') AND (h.origin IS DISTINCT FROM 'consumer' OR h.method IS NULL OR h.method NOT IN ('keyword', 'checkbox', 'written'))),
       false
  FROM consentvault.history_events h;
GRANT SELECT ON consentvault.post_history_permission_source TO consentvault_app, consentvault_worker, consentvault_console,
    consentvault_integrity, consentvault_isolation_self_test;

CREATE OR REPLACE VIEW consentvault.current_permission WITH (security_invoker = true) AS
WITH exploded AS (
    SELECT s.org_id, s.contact_kind, s.contact_norm, s.contact_fp, coalesce(s.contact_fp, s.contact_norm) AS ckey, s.event_type, s.rk,
           ch AS channel, pu AS purpose, s.hard_stop, s.valid_release
      FROM consentvault.post_history_permission_source s, unnest(s.channels) AS ch, unnest(s.purposes) AS pu
),
star AS (
    SELECT org_id, contact_kind, ckey, channel,
           max(rk) FILTER (WHERE event_type IN ('revoke', 'suppress')) AS star_stop_rk,
           max(rk) FILTER (WHERE hard_stop)                            AS star_hard_rk
    FROM exploded WHERE purpose = '*' GROUP BY org_id, contact_kind, ckey, channel
),
agg AS (
    SELECT x.org_id, x.contact_kind, x.ckey, x.contact_norm, x.contact_fp, x.channel, x.purpose,
           max(x.rk) FILTER (WHERE x.event_type = 'grant')                    AS grant_rk,
           greatest(max(x.rk) FILTER (WHERE x.event_type IN ('revoke', 'suppress')), s.star_stop_rk) AS stop_rk,
           greatest(max(x.rk) FILTER (WHERE x.hard_stop), s.star_hard_rk)      AS hard_stop_rk,
           max(x.rk) FILTER (WHERE x.valid_release)                           AS release_rk
    FROM exploded x LEFT JOIN star s USING (org_id, contact_kind, ckey, channel)
    GROUP BY x.org_id, x.contact_kind, x.ckey, x.contact_norm, x.contact_fp, x.channel, x.purpose, s.star_stop_rk, s.star_hard_rk
)
SELECT a.contact_kind, a.contact_norm, a.channel, a.purpose,
       (a.grant_rk IS NOT NULL AND a.hard_stop_rk IS NULL AND (a.stop_rk IS NULL OR coalesce(a.release_rk > a.stop_rk, false))) AS allowed,
       CASE
           WHEN a.stop_rk IS NOT NULL AND (a.hard_stop_rk IS NOT NULL OR a.release_rk IS NULL OR a.release_rk < a.stop_rk)
               THEN 'stopped:' || (SELECT w.event_type FROM consentvault.post_history_permission_source w WHERE w.org_id = a.org_id AND w.rk = a.stop_rk LIMIT 1)
           WHEN a.grant_rk IS NULL THEN 'no_grant'
           ELSE 'granted'
       END AS reason,
       (SELECT w.event_id FROM consentvault.post_history_permission_source w
         WHERE w.org_id = a.org_id AND w.rk = greatest(a.grant_rk, a.stop_rk, a.release_rk) LIMIT 1) AS deciding_event_id,
       a.org_id, a.contact_fp,
       'stopped-rule-0075'::text AS rule_set_version
FROM agg a;
