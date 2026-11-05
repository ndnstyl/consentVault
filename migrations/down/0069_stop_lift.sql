-- Reverses 0069_stop_lift.sql. Refuses while any stop lift exists: a down migration never destroys evidence.
-- Run it as a superuser (or a BYPASSRLS role), in one transaction; it re-creates the 0068 release guard.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regclass('consentvault.stop_lift') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0069 refused: consentvault.stop_lift is missing; 0069 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.stop_lift) THEN
        RAISE EXCEPTION 'consentvault down 0069 refused: the vault holds stop lifts';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.gate_decision WHERE evidence_status IN ('records_found', 'no_record_found')) THEN
        RAISE EXCEPTION 'consentvault down 0069 refused: the vault holds contact checks under the plain labels';
    END IF;
END
$$;

DROP TABLE consentvault.stop_lift;
DROP FUNCTION consentvault.check_stop_lift();

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

ALTER TABLE consentvault.gate_decision DROP CONSTRAINT gate_decision_evidence_status_check;
ALTER TABLE consentvault.gate_decision ADD CONSTRAINT gate_decision_evidence_status_check
    CHECK (evidence_status ~ '^(consent_record_found|stop_on_record|no_record|record_incomplete:.+|unavailable:.+)$');

COMMIT;
