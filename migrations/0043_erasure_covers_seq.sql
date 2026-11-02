-- An erasure covers the event ledger by sequence, never by clock. consentvault.erasure_coverage holds, for each completed
-- erasure, the head sequence of its organisation's event chain at completion. A row of the erased contact at or before that
-- sequence was sealed under the destroyed key and reads as erased; a later row belongs to a returning person and is checked
-- under the new key. A completed erasure with no coverage row is a break for every row of its contact, never a guess.
--
-- The row is written by the database: when a request turns completed, a trigger takes the organisation's ledger lock and
-- records the head. No role may insert, change or delete one. A completed request is a record the request guard never lets
-- change, so the sequence lives beside it, insert-only.
--
-- A request turns completed only once its contact's key is gone: the trigger refuses completion while the key exists, so
-- coverage is never recorded for rows whose key a hand could still delete later.
--
-- Requests completed before this migration are backfilled from the event ledger. The erasure's own stop event (recorded_by
-- "erasure:<id>:<seq>") was sealed under the key the erasure destroyed; every row of the contact sealed under that same key
-- carries the same contact commitment (the salt lives under the key, and a returning person's new key has a new salt). The
-- erasure covers through the last such row, so a row written while the erasure waited for delivery is covered too. A
-- completed request whose stop the ledger does not hold refuses the migration by name; nothing is guessed from a clock.
CREATE TABLE consentvault.erasure_coverage (
    org_id             uuid NOT NULL,
    erasure_id         uuid NOT NULL,
    covers_through_seq bigint NOT NULL CHECK (covers_through_seq >= 0),
    recorded_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, erasure_id)
);
CREATE TRIGGER erasure_coverage_no_change BEFORE UPDATE OR DELETE ON consentvault.erasure_coverage
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER erasure_coverage_no_truncate BEFORE TRUNCATE ON consentvault.erasure_coverage
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();
ALTER TABLE consentvault.erasure_coverage ENABLE ROW LEVEL SECURITY;
CREATE POLICY erasure_coverage_tenant ON consentvault.erasure_coverage USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));

-- The backfill reads every organisation, so it runs in a function owned by the operator role (which bypasses row security),
-- granted the columns it reads (and, while it is created, the schema right an owner needs).
-- Only rights the operator role lacks are granted, and only those are revoked afterwards: rights it already held stay.
CREATE TEMP TABLE erasure_coverage_lent ON COMMIT DROP AS
SELECT x.rel, x.col FROM (VALUES ('consentvault.erasure_request', 'org_id'), ('consentvault.erasure_request', 'erasure_id'),
                                 ('consentvault.erasure_request', 'status'), ('consentvault.erasure_request', 'completed_at'),
                                 ('consentvault.erasure_request', 'contact_fp'), ('consentvault.event', 'contact_fp'),
                                 ('consentvault.event', 'contact_commit'),
                                 ('consentvault.event', 'org_id'), ('consentvault.event', 'seq'),
                                 ('consentvault.event', 'source'), ('consentvault.event', 'recorded_by')) AS x (rel, col)
 WHERE NOT has_column_privilege('consentvault_operator', x.rel, x.col, 'SELECT')
UNION ALL
SELECT NULL, NULL WHERE NOT has_schema_privilege('consentvault_operator', 'consentvault', 'CREATE');
DO $$
DECLARE
    l record;
BEGIN
    FOR l IN SELECT rel, col FROM erasure_coverage_lent LOOP
        IF l.rel IS NULL THEN
            GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
        ELSE
            EXECUTE format('GRANT SELECT (%I) ON %s TO consentvault_operator', l.col, l.rel);
        END IF;
    END LOOP;
END
$$;
CREATE FUNCTION consentvault.erasure_coverage_backfill()
    RETURNS TABLE (org_id uuid, erasure_id uuid, stop_seq bigint, covers bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    WITH stops AS (
        SELECT r.org_id, r.erasure_id, r.contact_fp, r.completed_at,
               (SELECT max(e.seq) FROM consentvault.event e
                 WHERE e.org_id = r.org_id AND e.source = 'erasure'
                   AND (e.recorded_by LIKE 'erasure:' || r.erasure_id::text || ':%'
                        OR e.recorded_by LIKE 'erasure-unconfirmed:' || r.erasure_id::text || ':%')) AS stop_seq
          FROM consentvault.erasure_request r WHERE r.status = 'completed')
    SELECT s.org_id, s.erasure_id, s.stop_seq,
           (SELECT max(e.seq) FROM consentvault.event e
             WHERE e.org_id = s.org_id AND e.contact_fp = s.contact_fp
               AND e.contact_commit = (SELECT st.contact_commit FROM consentvault.event st
                                        WHERE st.org_id = s.org_id AND st.seq = s.stop_seq))
      FROM stops s ORDER BY s.completed_at, s.erasure_id;
$$;
ALTER FUNCTION consentvault.erasure_coverage_backfill() OWNER TO consentvault_operator;

DO $$
DECLARE
    missing integer;
    named   text;
BEGIN
    SELECT count(*), string_agg(b.erasure_id::text, ', ')
      INTO missing, named
      FROM consentvault.erasure_coverage_backfill() b WHERE b.stop_seq IS NULL;
    IF missing > 0 THEN
        RAISE EXCEPTION 'consentvault 0043 refused: % completed erasure(s) have no stop in the event ledger to fix the sequence they cover: %',
            missing, named USING ERRCODE = 'integrity_constraint_violation';
    END IF;
END
$$;
INSERT INTO consentvault.erasure_coverage (org_id, erasure_id, covers_through_seq)
SELECT b.org_id, b.erasure_id, b.covers FROM consentvault.erasure_coverage_backfill() b;

DROP FUNCTION consentvault.erasure_coverage_backfill();
DO $$
DECLARE
    l record;
BEGIN
    FOR l IN SELECT rel, col FROM erasure_coverage_lent LOOP
        IF l.rel IS NULL THEN
            REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
        ELSE
            EXECUTE format('REVOKE SELECT (%I) ON %s FROM consentvault_operator', l.col, l.rel);
        END IF;
    END LOOP;
END
$$;
ALTER TABLE consentvault.erasure_coverage FORCE ROW LEVEL SECURITY;

CREATE FUNCTION consentvault.erasure_request_cover() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM consentvault.contact_key k
                WHERE k.org_id OPERATOR(pg_catalog.=) NEW.org_id AND k.contact_fp OPERATOR(pg_catalog.=) NEW.contact_fp) THEN
        RAISE EXCEPTION 'consentvault.erasure_request: a request is completed only after its contact key is deleted; the contact key still exists'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    -- the head is read under the organisation's ledger lock: a writer still holding it commits first and is covered
    PERFORM pg_catalog.pg_advisory_xact_lock(consentvault.ledger_lock_key(NEW.org_id));
    INSERT INTO consentvault.erasure_coverage (org_id, erasure_id, covers_through_seq)
    SELECT NEW.org_id, NEW.erasure_id, coalesce(pg_catalog.max(e.seq), 0) FROM consentvault.event e
     WHERE e.org_id OPERATOR(pg_catalog.=) NEW.org_id;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.erasure_request_cover() FROM PUBLIC;
CREATE TRIGGER erasure_request_cover AFTER UPDATE ON consentvault.erasure_request
    FOR EACH ROW WHEN (NEW.status = 'completed' AND OLD.status <> 'completed')
    EXECUTE FUNCTION consentvault.erasure_request_cover();

GRANT SELECT ON consentvault.erasure_coverage TO consentvault_app, consentvault_console;
