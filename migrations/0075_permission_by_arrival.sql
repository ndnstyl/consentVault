-- A person's permission is read in the order their posts arrived, never the order the projection wrote their events (a crash
-- can project an earlier post after a later one). The permission view ranked events by event seq, which is projection order;
-- it now ranks by the arrival of the post the event cites (an event that cites none, an erasure's stop, by its own receipt
-- time), ties broken on the post's own seq and then the event's. The rank is one number (arrival in microseconds, then the
-- post's seq, then the event's seq) so the view's columns and every caller are unchanged; arrival_key_seq reads the event's seq
-- back out of it. Both lookups run as the owner, so the answer does not depend on the reader's evidence scope (a stop counts
-- the same under a capture token as under a read token); they read only the entered organisation's rows, return no personal
-- data, and are read-only.
CREATE FUNCTION consentvault.arrival_key(p_org uuid, p_event_id uuid, p_seq bigint, p_received timestamptz) RETURNS numeric
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.round(extract(epoch FROM coalesce(p.received_at, p_received)) * 1000000) * 1e30
           + coalesce(p.seq, 0)::numeric * 1e15 + p_seq::numeric
      FROM (SELECT 1) one
      LEFT JOIN LATERAL (SELECT rp.received_at, rp.seq FROM consentvault.event_source_post s
                           JOIN consentvault.raw_post rp ON rp.org_id OPERATOR(pg_catalog.=) s.org_id AND rp.post_id OPERATOR(pg_catalog.=) s.post_id
                          WHERE s.org_id OPERATOR(pg_catalog.=) p_org AND s.event_id OPERATOR(pg_catalog.=) p_event_id
                            AND s.role OPERATOR(pg_catalog.=) 'trigger' LIMIT 1) p ON true;
$$;
REVOKE ALL ON FUNCTION consentvault.arrival_key(uuid, uuid, bigint, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.arrival_key(uuid, uuid, bigint, timestamptz) TO consentvault_app, consentvault_worker;

CREATE FUNCTION consentvault.arrival_key_seq(p_key numeric) RETURNS bigint
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.mod(p_key, 1e15)::bigint;
$$;
REVOKE ALL ON FUNCTION consentvault.arrival_key_seq(numeric) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.arrival_key_seq(numeric) TO consentvault_app, consentvault_worker;

-- The arrival time of an event's post (its own receipt time when it cites none): what the proof shows as the event's time.
CREATE FUNCTION consentvault.arrival_at(p_org uuid, p_event_id uuid, p_received timestamptz) RETURNS timestamptz
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce((SELECT rp.received_at FROM consentvault.event_source_post s
                       JOIN consentvault.raw_post rp ON rp.org_id OPERATOR(pg_catalog.=) s.org_id AND rp.post_id OPERATOR(pg_catalog.=) s.post_id
                      WHERE s.org_id OPERATOR(pg_catalog.=) p_org AND s.event_id OPERATOR(pg_catalog.=) p_event_id
                        AND s.role OPERATOR(pg_catalog.=) 'trigger' LIMIT 1), p_received);
$$;
REVOKE ALL ON FUNCTION consentvault.arrival_at(uuid, uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.arrival_at(uuid, uuid, timestamptz) TO consentvault_app, consentvault_worker;

-- Every login that may read the view needs the functions it calls: the operator console and the isolation self-test (which reads
-- every tenant view and finds one it cannot read as a finding).
GRANT EXECUTE ON FUNCTION consentvault.arrival_key(uuid, uuid, bigint, timestamptz), consentvault.arrival_key_seq(numeric),
    consentvault.arrival_at(uuid, uuid, timestamptz) TO consentvault_console, consentvault_isolation_self_test;

CREATE OR REPLACE VIEW consentvault.current_permission WITH (security_invoker = true) AS
WITH exploded AS (
    SELECT e.org_id, e.contact_kind, e.contact_norm, e.contact_fp,
           coalesce(e.contact_fp, e.contact_norm) AS ckey,
           e.event_type,
           CASE WHEN e.event_type = 'release'
                THEN (SELECT consentvault.arrival_key(g.org_id, g.event_id, g.seq, g.received_at) FROM consentvault.event g
                       WHERE g.org_id = e.org_id AND g.event_id = e.release_of_event_id)
                ELSE consentvault.arrival_key(e.org_id, e.event_id, e.seq, e.received_at) END AS rk,
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
                                    WHERE org_id = a.org_id AND seq = consentvault.arrival_key_seq(a.stop_rk))
           WHEN a.grant_rk IS NULL THEN 'no_grant'
           ELSE 'granted'
       END AS reason,
       (SELECT event_id FROM consentvault.event
         WHERE org_id = a.org_id AND seq = consentvault.arrival_key_seq(greatest(a.grant_rk, a.stop_rk, a.release_rk))) AS deciding_event_id,
       a.org_id, a.contact_fp
FROM agg a;
