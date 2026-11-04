-- Reverses 0068_release_needs_no_verification.sql: the release guard again refuses a lift on a grant whose contact point was not verified
BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                   WHERE n.nspname = 'consentvault' AND p.proname = 'check_release_ref'
                     AND p.prosrc NOT LIKE '%verified%') THEN
        RAISE EXCEPTION 'consentvault down 0068 refused: 0068 is not applied';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION consentvault.check_release_ref() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    g_channels pg_catalog.text[];
    g_purposes pg_catalog.text[];
    g_verification pg_catalog.text;
BEGIN
    IF NEW.event_type OPERATOR(pg_catalog.<>) 'release' THEN
        RETURN NEW;
    END IF;
    SELECT g.channels, g.purposes, g.contact_verification INTO g_channels, g_purposes, g_verification
    FROM consentvault.event g
    WHERE g.org_id OPERATOR(pg_catalog.=) NEW.org_id
      AND g.event_id OPERATOR(pg_catalog.=) NEW.release_of_event_id
      AND g.event_type OPERATOR(pg_catalog.=) 'grant'
      AND g.origin OPERATOR(pg_catalog.=) 'consumer'
      AND g.contact_kind OPERATOR(pg_catalog.=) NEW.contact_kind
      AND g.contact_norm IS NOT DISTINCT FROM NEW.contact_norm
      AND g.contact_fp IS NOT DISTINCT FROM NEW.contact_fp
      AND g.seq OPERATOR(pg_catalog.<) NEW.seq;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault release: a release must decide an earlier consumer grant of the same contact point'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NOT (NEW.channels OPERATOR(pg_catalog.<@) g_channels AND NEW.purposes OPERATOR(pg_catalog.<@) g_purposes) THEN
        RAISE EXCEPTION 'consentvault release: a release may name only the channels and purposes of the grant it decides'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.release_outcome OPERATOR(pg_catalog.=) 'released'
       AND g_verification OPERATOR(pg_catalog.<>) ALL (ARRAY['otp', 'inbound_keyword']::pg_catalog.text[]) THEN
        RAISE EXCEPTION 'consentvault release: only a grant whose contact point was verified (one-time code or inbound keyword) can lift a stop'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

COMMIT;
