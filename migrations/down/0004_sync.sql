-- Reverses 0004_sync.sql. Refuses while the vault holds delivery history: a connected system, a queued or delivered
-- push, a delivery receipt, an inbound signal or a redrive. A down migration never destroys evidence of what was told
-- to whom, and a re-applied migration would restart the version counters the receivers have already seen.
--
-- Run it as a superuser (or a BYPASSRLS role), in one transaction. Row security is switched off for the transaction,
-- so a role that row-level security would filter gets an error instead of counting zero rows and dropping history.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regclass('consentvault.outbox') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0004 refused: consentvault.outbox is missing; 0004 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.connected_system) OR EXISTS (SELECT 1 FROM consentvault.outbox)
       OR EXISTS (SELECT 1 FROM consentvault.delivery) OR EXISTS (SELECT 1 FROM consentvault.inbound_signal)
       OR EXISTS (SELECT 1 FROM consentvault.redrive_run) THEN
        RAISE EXCEPTION 'consentvault down 0004 refused: the vault holds connected systems or delivery history';
    END IF;
END
$$;

DROP FUNCTION consentvault.sync_redrive_status(uuid);
DROP FUNCTION consentvault.sync_redrive_start(uuid, text, text);
DROP FUNCTION consentvault.sync_deliveries_of_contact(text, uuid, integer, timestamptz, uuid);
DROP FUNCTION consentvault.sync_deliveries_of_system(uuid, text, timestamptz, timestamptz, integer, timestamptz, uuid);
DROP FUNCTION consentvault.sync_refresh_redrives();
DROP FUNCTION consentvault.sync_redrive_refresh(uuid);
DROP FUNCTION consentvault.sync_ack_alarms(uuid[]);
DROP FUNCTION consentvault.sync_dead_groups();
DROP FUNCTION consentvault.sync_release(uuid, integer, timestamptz);
DROP FUNCTION consentvault.sync_complete(uuid, integer, text, integer, text, bytea, timestamptz, timestamptz);
DROP FUNCTION consentvault.sync_claim(integer, integer, timestamptz);
DROP FUNCTION consentvault.sync_signal_record(uuid, uuid, text, text, text, text, timestamptz, text, uuid, bytea, text);
DROP FUNCTION consentvault.sync_signal_lookup(uuid, text);
DROP FUNCTION consentvault.sync_ledger_state(text, text, text);
DROP FUNCTION consentvault.sync_system_of_credential(uuid);
DROP FUNCTION consentvault.sync_system_bind_credential(uuid, uuid);
DROP FUNCTION consentvault.sync_enqueue(uuid, uuid, text, text, text, integer, bytea);
DROP FUNCTION consentvault.sync_targets();
DROP FUNCTION consentvault.sync_advance_state(uuid, text);
DROP TABLE consentvault.inbound_signal;
DROP TABLE consentvault.delivery;
DROP TABLE consentvault.outbox;
DROP TABLE consentvault.redrive_run;
DROP TABLE consentvault.state_version;
DROP TABLE consentvault.connected_system;
DROP FUNCTION consentvault.sync_org(text[]);
COMMIT;
