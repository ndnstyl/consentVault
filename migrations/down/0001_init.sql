-- Refuses to run while the ledger holds any event: a down migration never destroys evidence.
DO $$
DECLARE
    has_rows boolean;
BEGIN
    IF to_regclass('consentvault.event') IS NOT NULL THEN
        EXECUTE 'SELECT EXISTS (SELECT 1 FROM consentvault.event)' INTO has_rows;
        IF has_rows THEN
            RAISE EXCEPTION 'consentvault down migration refused: consentvault.event holds events; export them and remove the schema by hand if you mean to destroy them';
        END IF;
    END IF;
END
$$;

DROP VIEW IF EXISTS consentvault.current_permission;
DROP VIEW IF EXISTS consentvault.unsealed_events;
DROP VIEW IF EXISTS consentvault.chain_breaks;
DROP TABLE IF EXISTS consentvault.review;
DROP TABLE IF EXISTS consentvault.contact_log;
DROP TABLE IF EXISTS consentvault.chain_head;
DROP TABLE IF EXISTS consentvault.seal;
DROP TABLE IF EXISTS consentvault.event;
DROP TABLE IF EXISTS consentvault.contact_salt;
DROP TABLE IF EXISTS consentvault.disclosure;
DROP FUNCTION IF EXISTS consentvault.mark_seal_verified(bigint);
DROP FUNCTION IF EXISTS consentvault.check_contact_salt();
DROP FUNCTION IF EXISTS consentvault.mint_contact_salt(text);
DROP FUNCTION IF EXISTS consentvault.check_release_ref();
DROP FUNCTION IF EXISTS consentvault.check_received_at();
DROP FUNCTION IF EXISTS consentvault.check_grant_scope();
DROP FUNCTION IF EXISTS consentvault.check_chain_head();
DROP FUNCTION IF EXISTS consentvault.seal_guard();
DROP FUNCTION IF EXISTS consentvault.refuse_change();
-- The group role consentvault_app is cluster-wide and is left in place; drop it by hand if nothing else uses it.
