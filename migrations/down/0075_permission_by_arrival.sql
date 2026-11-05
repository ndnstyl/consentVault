-- Reverses 0075_permission_by_arrival.sql: the permission view ranks by event seq again (projection order); the three arrival
-- functions are dropped. Nothing stored is touched.
BEGIN;
CREATE OR REPLACE VIEW consentvault.current_permission WITH (security_invoker = true) AS
WITH exploded AS (
    SELECT e.org_id, e.contact_kind, e.contact_norm, e.contact_fp,
           coalesce(e.contact_fp, e.contact_norm) AS ckey,
           e.event_type,
           CASE WHEN e.event_type = 'release'
                THEN (SELECT g.seq FROM consentvault.event g
                       WHERE g.org_id = e.org_id AND g.event_id = e.release_of_event_id)
                ELSE e.seq END AS rk,
           ch AS channel, pu AS purpose,
           (e.event_type IN ('revoke', 'suppress')
              AND (e.origin <> 'consumer' OR e.method NOT IN ('keyword', 'checkbox', 'written'))) AS hard_stop,
           (e.event_type = 'release' AND e.origin = 'consumer' AND e.release_outcome = 'released') AS valid_release
    FROM consentvault.event e, unnest(e.channels) AS ch, unnest(e.purposes) AS pu
),
star AS (
    SELECT org_id, contact_kind, ckey, channel,
           max(rk) FILTER (WHERE event_type IN ('revoke', 'suppress')) AS star_stop_rk,
           max(rk) FILTER (WHERE hard_stop)                            AS star_hard_rk
    FROM exploded
    WHERE purpose = '*'
    GROUP BY org_id, contact_kind, ckey, channel
),
agg AS (
    SELECT x.org_id, x.contact_kind, x.ckey, x.contact_norm, x.contact_fp, x.channel, x.purpose,
           max(x.rk) FILTER (WHERE x.event_type = 'grant')                    AS grant_rk,
           greatest(max(x.rk) FILTER (WHERE x.event_type IN ('revoke', 'suppress')), s.star_stop_rk) AS stop_rk,
           greatest(max(x.rk) FILTER (WHERE x.hard_stop), s.star_hard_rk)      AS hard_stop_rk,
           max(x.rk) FILTER (WHERE x.valid_release)                           AS release_rk
    FROM exploded x
    LEFT JOIN star s USING (org_id, contact_kind, ckey, channel)
    GROUP BY x.org_id, x.contact_kind, x.ckey, x.contact_norm, x.contact_fp, x.channel, x.purpose,
             s.star_stop_rk, s.star_hard_rk
)
SELECT a.contact_kind, a.contact_norm, a.channel, a.purpose,
       (a.grant_rk IS NOT NULL AND a.hard_stop_rk IS NULL
            AND (a.stop_rk IS NULL OR coalesce(a.release_rk > a.stop_rk, false))) AS allowed,
       CASE
           WHEN a.stop_rk IS NOT NULL
                AND (a.hard_stop_rk IS NOT NULL OR a.release_rk IS NULL OR a.release_rk < a.stop_rk)
               THEN 'stopped:' || (SELECT event_type FROM consentvault.event
                                    WHERE org_id = a.org_id AND seq = a.stop_rk)
           WHEN a.grant_rk IS NULL THEN 'no_grant'
           ELSE 'granted'
       END AS reason,
       (SELECT event_id FROM consentvault.event
         WHERE org_id = a.org_id AND seq = greatest(a.grant_rk, a.stop_rk, a.release_rk)) AS deciding_event_id,
       a.org_id, a.contact_fp
FROM agg a;
DROP FUNCTION consentvault.arrival_at(uuid, uuid, timestamptz);
DROP FUNCTION consentvault.arrival_key_seq(numeric);
DROP FUNCTION consentvault.arrival_key(uuid, uuid, bigint, timestamptz);
COMMIT;
