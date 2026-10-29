-- Reverses 0009_notify.sql. Refuses while the send log holds any row: the log is the record of what was sent and a
-- down migration never destroys it.
-- Run it as a superuser (or a BYPASSRLS role), in one transaction.
BEGIN;

DO $$
BEGIN
    IF to_regclass('consentvault.notify_send_log') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0009 refused: consentvault.notify_send_log is missing; 0009 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.notify_send_log) THEN
        RAISE EXCEPTION 'consentvault down 0009 refused: the send log holds rows';
    END IF;
END
$$;

DROP TABLE consentvault.notify_send_log;

COMMIT;
