-- Reverses 0045_audit_detail.sql. Run it as a superuser, in one transaction. A chain row that carries a detail was hashed with
-- the detail, so the down refuses while any such row exists: removing the column would turn those rows into breaks.
BEGIN;

DO $$
BEGIN
    IF to_regprocedure('consentvault.append_audit_detailed(text, text, text, text, text, text, text, jsonb)') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0045 refused: 0045 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.audit_event WHERE detail IS NOT NULL) THEN
        RAISE EXCEPTION 'consentvault down 0045 refused: audit rows carry a detail the chain hashed; they would read as breaks'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF to_regclass('consentvault_guard.pin') IS NOT NULL THEN
        DELETE FROM consentvault_guard.pin WHERE identity IN ('consentvault.audit_chain_guard()');
    END IF;
END
$$;

DROP FUNCTION consentvault.append_audit_detailed(text, text, text, text, text, text, text, jsonb);

CREATE OR REPLACE VIEW consentvault.audit_chain_breaks WITH (security_invoker = true) AS
SELECT org_id, seq, audit_id,
       CASE WHEN expected_seq <> seq THEN 'seq_gap'
            WHEN expected_prev <> prev_hash THEN 'prev_hash_mismatch'
            ELSE 'row_hash_mismatch' END AS reason
FROM (
    SELECT a.org_id, a.seq, a.audit_id, a.prev_hash,
           coalesce(lag(a.seq) OVER w + 1, 1) AS expected_seq,
           coalesce(lag(a.row_hash) OVER w, repeat('0', 64)) AS expected_prev,
           a.row_hash,
           consentvault.audit_row_hash(a.prev_hash, a.org_id, a.seq, a.actor_kind, a.actor_id, a.action, a.target_kind,
                                       a.target_id, a.reason, a.request_id, a.at) AS recomputed
    FROM consentvault.audit_event a
    WINDOW w AS (PARTITION BY a.chain_key ORDER BY a.seq)
) t
WHERE expected_seq <> seq OR expected_prev <> prev_hash OR recomputed <> row_hash;

CREATE OR REPLACE FUNCTION consentvault.audit_chain_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    h record;
    ck uuid := coalesce(NEW.org_id, '00000000-0000-0000-0000-000000000000'::uuid);  -- generated columns are not yet set in a BEFORE trigger
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('consentvault.audit:' || ck::text));
    SELECT seq, row_hash INTO h FROM consentvault.audit_event
     WHERE chain_key OPERATOR(pg_catalog.=) ck ORDER BY seq DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.seq OPERATOR(pg_catalog.<>) 1 OR NEW.prev_hash OPERATOR(pg_catalog.<>) repeat('0', 64) THEN
            RAISE EXCEPTION 'consentvault audit: the first row of a chain is seq 1 on the zero hash' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF NEW.seq OPERATOR(pg_catalog.<>) h.seq + 1 OR NEW.prev_hash OPERATOR(pg_catalog.<>) h.row_hash THEN
        RAISE EXCEPTION 'consentvault audit: a row must extend the head of its chain (fork or gap refused)' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.row_hash OPERATOR(pg_catalog.<>) consentvault.audit_row_hash(NEW.prev_hash, NEW.org_id, NEW.seq, NEW.actor_kind,
            NEW.actor_id, NEW.action, NEW.target_kind, NEW.target_id, NEW.reason, NEW.request_id, NEW.at) THEN
        RAISE EXCEPTION 'consentvault audit: row_hash does not match the row' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP FUNCTION consentvault.audit_row_hash(text, uuid, bigint, text, text, text, text, text, text, text, timestamptz, jsonb);
ALTER TABLE consentvault.audit_event DROP COLUMN detail;
COMMIT;
