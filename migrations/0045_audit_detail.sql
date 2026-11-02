-- The audit row gains an optional detail object (members.md amendment): record ids and counts an action touched, never a
-- contact point, a name, a company or a reply text. Additive: a row with no detail hashes exactly as it did, so every chain
-- written before this migration still verifies.
--
-- * audit_event.detail: a JSON object or null.
-- * audit_row_hash gains a twelfth argument. With no detail it answers the 'audit.v1' hash of the eleven-argument form; with a
--   detail it hashes 'audit.v2' over the same fields and the detail text (jsonb prints keys in one fixed order), so the
--   detail is covered by the chain like every other field.
-- * The chain guard and the verification view recompute with the detail; append_audit_detailed takes the detail as an eighth argument
--   (append_audit stays and writes a row with no detail).
ALTER TABLE consentvault.audit_event
    ADD COLUMN detail jsonb CHECK (detail IS NULL OR (jsonb_typeof(detail) = 'object' AND octet_length(detail::text) <= 16777216));

CREATE FUNCTION consentvault.audit_row_hash(p_prev text, p_org uuid, p_seq bigint, p_actor_kind text, p_actor_id text,
        p_action text, p_target_kind text, p_target_id text, p_reason text, p_request_id text, p_at timestamptz,
        p_detail jsonb)
    RETURNS text LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN p_detail IS NULL
                THEN consentvault.audit_row_hash(p_prev, p_org, p_seq, p_actor_kind, p_actor_id, p_action, p_target_kind,
                                                 p_target_id, p_reason, p_request_id, p_at)
                ELSE encode(sha256(convert_to(concat_ws(E'\x1f', 'audit.v2', p_prev, coalesce(p_org::text, 'platform'),
                        p_seq::text, p_actor_kind, coalesce(p_actor_id, ''), p_action, p_target_kind,
                        coalesce(p_target_id, ''), coalesce(p_reason, ''), p_request_id,
                        ((extract(epoch FROM p_at) * 1000000)::bigint)::text, p_detail::text), 'UTF8')), 'hex') END;
$$;
GRANT EXECUTE ON FUNCTION consentvault.audit_row_hash(text, uuid, bigint, text, text, text, text, text, text, text,
        timestamptz, jsonb) TO consentvault_app, consentvault_worker;

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
            NEW.actor_id, NEW.action, NEW.target_kind, NEW.target_id, NEW.reason, NEW.request_id, NEW.at, NEW.detail) THEN
        RAISE EXCEPTION 'consentvault audit: row_hash does not match the row' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

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
                                       a.target_id, a.reason, a.request_id, a.at, a.detail) AS recomputed
    FROM consentvault.audit_event a
    WINDOW w AS (PARTITION BY a.chain_key ORDER BY a.seq)
) t
WHERE expected_seq <> seq OR expected_prev <> prev_hash OR recomputed <> row_hash;

GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
CREATE FUNCTION consentvault.append_audit_detailed(p_actor_kind text, p_actor_id text, p_action text, p_target_kind text,
        p_target_id text, p_reason text, p_request_id text, p_detail jsonb) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org  uuid := (SELECT consentvault.current_org());
    h    record;
    nseq bigint;
    prev text;
    stamp timestamptz := clock_timestamp();
    rh   text;
    id   uuid := gen_random_uuid();
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault audit: an audit row needs an entered tenant' USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('consentvault.audit:' || org::text));
    SELECT a.seq, a.row_hash INTO h FROM consentvault.audit_event a WHERE a.org_id = org ORDER BY a.seq DESC LIMIT 1;
    IF FOUND THEN nseq := h.seq + 1; prev := h.row_hash; ELSE nseq := 1; prev := repeat('0', 64); END IF;
    rh := consentvault.audit_row_hash(prev, org, nseq, p_actor_kind, p_actor_id, p_action, p_target_kind, p_target_id,
                                      p_reason, p_request_id, stamp, p_detail);
    INSERT INTO consentvault.audit_event (audit_id, org_id, seq, actor_kind, actor_id, action, target_kind, target_id,
                                          reason, request_id, at, prev_hash, row_hash, detail)
    VALUES (id, org, nseq, p_actor_kind, p_actor_id, p_action, p_target_kind, p_target_id, p_reason, p_request_id,
            stamp, prev, rh, p_detail);
    RETURN id;
END;
$$;
ALTER FUNCTION consentvault.append_audit_detailed(text, text, text, text, text, text, text, jsonb) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.append_audit_detailed(text, text, text, text, text, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.append_audit_detailed(text, text, text, text, text, text, text, jsonb)
    TO consentvault_app, consentvault_console;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
