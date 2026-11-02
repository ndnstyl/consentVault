-- The integrity jobs (seal, verify-seals, verify-chain, anchor) in multi-tenant mode run as their own group role,
-- consentvault_integrity, through a dedicated login. In multi mode a login without a tenant token sees no rows under row
-- security, so these jobs must take one token per organisation from the database and work inside each in turn.
--
-- What the group may do, and nothing more:
--   * list the organisations and mint each one's token just before working in it (dispatch_org_ids,
--     dispatch_org_token, as the sync worker does) and enter an organisation with one (enter_org, current_org);
--   * read, under that token, what the runtime role reads for these jobs: event, seal, chain_head, unsealed_events,
--     the ledger head and the home organisation's id;
--   * write what these jobs already write: a new seal row and a new chain_head row (both append-only), and a seal's
--     verified time through mark_seal_verified (verify-seals).
-- It holds no other function, no UPDATE, DELETE or TRUNCATE, and no read of contacts, logs, reviews, the outbox or keys.
-- Row-level security binds it like every role (the policies are on PUBLIC).
--
-- The role is made once per cluster by a superuser (docker/initdb/10-roles.sh, or the managed database's master user).

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_integrity') THEN
        RAISE EXCEPTION 'consentvault migration 0048 refused: the role consentvault_integrity does not exist. As a superuser '
                        '(or the managed database master user) run: CREATE ROLE consentvault_integrity NOLOGIN; then '
                        'create its login as a member of it (docs/selfhost.md, "Roles")'
            USING ERRCODE = 'undefined_object';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_integrity'
                AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
        RAISE EXCEPTION 'consentvault migration 0048 refused: consentvault_integrity must be a NOLOGIN group, neither a '
                        'superuser nor BYPASSRLS'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA consentvault TO consentvault_integrity;
GRANT EXECUTE ON FUNCTION consentvault.dispatch_org_ids(text), consentvault.dispatch_org_token(text, uuid), consentvault.enter_org(text), consentvault.current_org(),
    consentvault.home_org(), consentvault.ledger_head(), consentvault.current_token_scopes(),
    consentvault.may_read_evidence(), consentvault.mark_seal_verified(uuid) TO consentvault_integrity;
GRANT SELECT ON consentvault.event, consentvault.seal, consentvault.chain_head, consentvault.unsealed_events
    TO consentvault_integrity;
GRANT INSERT ON consentvault.seal, consentvault.chain_head TO consentvault_integrity;

-- The evidence read scope (row security on event and the contact tables) admits the runtime's read scopes. A token the
-- token handout mints for one of these four jobs ('worker:seal', 'worker:verify_seals', 'worker:verify_chain',
-- 'worker:anchor') reads too, but only for a login in the integrity group: the sync worker can mint the same scopes and
-- still reads nothing. Same body as 0002 otherwise.
CREATE OR REPLACE FUNCTION consentvault.may_read_evidence() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.event'::regclass)
        OR coalesce(current_setting('consentvault.org_token', true), '') = ''
        OR coalesce(consentvault.current_token_scopes() && ARRAY['gate_read', 'proof_read', 'admin'], false)
        OR (coalesce(consentvault.current_token_scopes()
                     && ARRAY['worker:seal', 'worker:verify_seals', 'worker:verify_chain', 'worker:anchor'], false)
            AND pg_has_role(current_user, 'consentvault_integrity', 'MEMBER'));
$$;
