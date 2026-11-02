-- Undo 0048: the evidence read scope goes back to its 0002 body, and the integrity group loses every grant 0048 gave
-- it. The role itself (made by a superuser) is left in place.
CREATE OR REPLACE FUNCTION consentvault.may_read_evidence() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.event'::regclass)
        OR coalesce(current_setting('consentvault.org_token', true), '') = ''
        OR coalesce(consentvault.current_token_scopes() && ARRAY['gate_read', 'proof_read', 'admin'], false);
$$;
REVOKE INSERT ON consentvault.seal, consentvault.chain_head FROM consentvault_integrity;
REVOKE SELECT ON consentvault.event, consentvault.seal, consentvault.chain_head, consentvault.unsealed_events
    FROM consentvault_integrity;
REVOKE EXECUTE ON FUNCTION consentvault.dispatch_org_ids(text), consentvault.dispatch_org_token(text, uuid), consentvault.enter_org(text), consentvault.current_org(),
    consentvault.home_org(), consentvault.ledger_head(), consentvault.current_token_scopes(),
    consentvault.may_read_evidence(), consentvault.mark_seal_verified(uuid) FROM consentvault_integrity;
REVOKE USAGE ON SCHEMA consentvault FROM consentvault_integrity;
