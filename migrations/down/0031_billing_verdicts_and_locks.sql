-- Reverses 0031_billing_verdicts_and_locks.sql. Run it as the schema owner, in one transaction. Verdicts and retry times go with the columns.
BEGIN;

DO $$
BEGIN
    IF to_regprocedure('consentvault.billing_lock_account(uuid)') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0031 refused: 0031 is not applied';
    END IF;
END
$$;

DROP FUNCTION consentvault.billing_alarm_open(uuid, text);
DROP FUNCTION consentvault.billing_lock_account(uuid);
DROP FUNCTION consentvault.usage_retry_due(timestamptz);
DROP FUNCTION consentvault.usage_acknowledge(date, text, text);
DROP FUNCTION consentvault.usage_clear_verdict(date, text);
DROP FUNCTION consentvault.usage_note_verdict(date, text);
DROP FUNCTION consentvault.usage_clear_send(date, text);
ALTER TABLE consentvault.usage_day DROP COLUMN retry_at;
ALTER TABLE consentvault.usage_day DROP COLUMN stripe_verdict;

COMMIT;
