-- Reverses 0114_stop_notice.sql: the stop notices, their email queue, acknowledgements and added recipients go with their tables.
BEGIN;

DO $$
BEGIN
    IF to_regclass('consentvault.stop_notice') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0114 refused: 0114 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.notify_send_log WHERE type = 'stop_notice') THEN
        RAISE EXCEPTION 'consentvault down 0114 refused: the send log holds stop_notice rows (append-only); keep the type';
    END IF;
END
$$;

DROP FUNCTION consentvault.stop_notice_acknowledge(uuid, uuid[]);
DROP FUNCTION consentvault.stop_notice_unacknowledged(uuid);
DROP FUNCTION consentvault.stop_notice_delivery(uuid[]);
DROP FUNCTION consentvault.stop_notice_mail_done(uuid[], boolean);
DROP FUNCTION consentvault.stop_notice_due(integer, integer);
DROP FUNCTION consentvault.stop_notice_record(uuid, uuid, text, text, text[], text[], jsonb, timestamptz);
DROP TABLE consentvault.stop_notice_ack;
DROP TABLE consentvault.stop_notice_mail;
DROP TABLE consentvault.stop_notice_recipient;
DROP TABLE consentvault.stop_notice;
ALTER TABLE consentvault.notify_send_log DROP CONSTRAINT notify_send_log_type_check;
ALTER TABLE consentvault.notify_send_log ADD CONSTRAINT notify_send_log_type_check
    CHECK (type IN ('invite', 'security_alert', 'delivery_failure', 'billing_notice'));

COMMIT;
