-- A grant the person makes on a form after their own stop takes effect: the release guard no longer asks for a
-- verified contact point. The guard still requires an earlier consumer grant of the same contact point and names
-- only that grant's channels and purposes.
BEGIN;

CREATE OR REPLACE FUNCTION consentvault.check_release_ref() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    g_channels pg_catalog.text[];
    g_purposes pg_catalog.text[];
BEGIN
    IF NEW.event_type OPERATOR(pg_catalog.<>) 'release' THEN
        RETURN NEW;
    END IF;
    SELECT g.channels, g.purposes INTO g_channels, g_purposes
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
    RETURN NEW;
END;
$$;

COMMIT;
