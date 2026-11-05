-- The match writer's one read: the posts already linked to a contact fingerprint, in the order the infrastructure recorded
-- their arrival, with the ciphertext the writer needs to compare a new post against them.
--
-- A capture token writes but cannot read back (the evidence read scope on every raw-post table), and the link step runs on the
-- capture path under that token. So the read is one definer function, scoped to the current organisation, that returns only
-- what linking needs and nothing a person could be named from: ids, the arrival order, the body digest, the post's wrapped
-- data key (opened only by the vault's key provider), the encrypted consent and wording readings under the map in force at
-- arrival (the lowest map version), the encrypted source id fact, and the contact's active record, if it has one. Nothing here
-- decides anything and nothing is written.

CREATE FUNCTION consentvault.match_lookup(p_contact_fp text)
    RETURNS TABLE (record_id uuid, post_id uuid, seq bigint, order_at timestamptz, body_sha256 text, encryption text,
                   post_key_wrapped bytea, key_version integer, map_version integer, consent_state text, consent_ct bytea,
                   wording_state text, wording_ct bytea, source_ct bytea)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.current_org();
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault match_lookup: no tenant entered' USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    IF p_contact_fp IS NULL OR p_contact_fp !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'consentvault match_lookup: the fingerprint must be 64 hex characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- always at least one row: the contact's active record (null when it has none) with a null post when nothing is linked yet
    RETURN QUERY
    SELECT rec.record_id, x.post_id, x.seq, x.order_at, x.body_sha256, x.encryption, x.post_key_wrapped, x.key_version,
           x.map_version, x.consent_state, x.consent_ct, x.wording_state, x.wording_ct, x.source_ct
      FROM (SELECT (SELECT r.record_id FROM consentvault.record r
                     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND r.erased_at IS NULL) AS record_id) rec
      LEFT JOIN LATERAL (
        SELECT p.post_id, p.seq, coalesce(p.edge_received_at, p.received_at) AS order_at, p.body_sha256, p.encryption,
               k.post_key_wrapped, k.key_version, v.mv AS map_version, c.state AS consent_state, c.values_ct AS consent_ct,
               w.state AS wording_state, w.values_ct AS wording_ct,
               (SELECT f.value_ct FROM consentvault.raw_post_fact f
                 WHERE f.org_id = org AND f.post_id = p.post_id AND f.name = 'capture_source_id'
                 ORDER BY f.recorded_at DESC, f.fact_id DESC LIMIT 1) AS source_ct
          FROM (SELECT DISTINCT m.post_id FROM consentvault.raw_post_match m
                 WHERE m.org_id = org AND m.contact_fp = p_contact_fp AND m.status = 'matched') l
          JOIN consentvault.raw_post p ON p.org_id = org AND p.post_id = l.post_id
          LEFT JOIN consentvault.raw_post_key k ON k.org_id = org AND k.post_id = p.post_id
          LEFT JOIN LATERAL (SELECT min(f.map_version) AS mv FROM consentvault.raw_post_field f
                              WHERE f.org_id = org AND f.post_id = p.post_id) v ON true
          LEFT JOIN consentvault.raw_post_field c
                 ON c.org_id = org AND c.post_id = p.post_id AND c.map_version = v.mv AND c.field = 'consent'
          LEFT JOIN consentvault.raw_post_field w
                 ON w.org_id = org AND w.post_id = p.post_id AND w.map_version = v.mv AND w.field = 'wording'
      ) x ON true
     ORDER BY x.order_at, x.seq;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.match_lookup(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.match_lookup(text) TO consentvault_app, consentvault_console;
