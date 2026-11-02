-- Reverses 0029_billing_sent_marks.sql. Run it as the schema owner, in one transaction. The sent marks go with the column.
BEGIN;

DO $$
BEGIN
    IF to_regprocedure('consentvault.usage_claim_send(date, text)') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0029 refused: 0029 is not applied';
    END IF;
END
$$;

DROP FUNCTION consentvault.billing_held_subscription(uuid);
DROP FUNCTION consentvault.usage_claim_send(date, text);
ALTER TABLE consentvault.usage_day DROP COLUMN stripe_sent;

COMMIT;
