-- Reverses 0047_confirmations.sql. Run it as a superuser (the trigger guard refuses the removal of an append-only trigger for
-- anyone else), in one transaction, after 0049 is reversed. Everything the confirmation service stored goes with its table:
-- sending accounts and their sealed credentials, rules, templates, the queue, what was sent and what was received.
BEGIN;

DO $$
BEGIN
    IF to_regclass('consentvault.confirmation_send_intent') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0047 refused: 0047 is not applied';
    END IF;
    IF to_regclass('consentvault_guard.pin') IS NOT NULL THEN
        DELETE FROM consentvault_guard.pin WHERE identity IN (
            'confirmation_send_append_only on consentvault.confirmation_send',
            'confirmation_send_status_append_only on consentvault.confirmation_send_status',
            'confirmation_inbound_seen_append_only on consentvault.confirmation_inbound_seen');
    END IF;
    IF to_regclass('consentvault_guard.table_pin') IS NOT NULL THEN
        DELETE FROM consentvault_guard.table_pin WHERE rel IN (
            'consentvault.confirmation_send'::regclass, 'consentvault.confirmation_send_status'::regclass,
            'consentvault.confirmation_inbound_seen'::regclass);
    END IF;
END
$$;

DROP TABLE consentvault.confirmation_page_token;
DROP TABLE consentvault.confirmation_inbound_failure;
DROP TABLE consentvault.confirmation_inbound_seen;
DROP TABLE consentvault.confirmation_connect_test;
DROP TABLE consentvault.confirmation_reply;
DROP TABLE consentvault.confirmation_send_status;
DROP TABLE consentvault.confirmation_send;
DROP TABLE consentvault.confirmation_send_intent;
DROP TABLE consentvault.confirmation_rule;
DROP TABLE consentvault.confirmation_template;
DROP TABLE consentvault.confirmation_registration;
DROP TABLE consentvault.confirmation_link_host;
DROP TABLE consentvault.confirmation_settings;
DROP TABLE consentvault.sending_account;

COMMIT;
