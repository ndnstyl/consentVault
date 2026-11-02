-- Reverses 0053_setup.sql: the skip marks of the setup steps go with their table. Nothing else stored setup progress.
BEGIN;

DO $$
BEGIN
    IF to_regclass('consentvault.setup_step_skip') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0053 refused: 0053 is not applied';
    END IF;
END
$$;

DROP TABLE consentvault.setup_step_skip;

COMMIT;
