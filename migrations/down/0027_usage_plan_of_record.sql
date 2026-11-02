-- Reverses 0027_usage_plan_of_record.sql. Run it as the schema owner, in one transaction.
BEGIN;

DO $$
BEGIN
    IF to_regprocedure('consentvault.usage_plan_of_record()') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0027 refused: 0027 is not applied';
    END IF;
END
$$;

DROP FUNCTION consentvault.usage_unreported_days(date, date);
DROP FUNCTION consentvault.usage_plan_of_record();

COMMIT;
