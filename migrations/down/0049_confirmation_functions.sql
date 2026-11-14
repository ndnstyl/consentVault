-- Reverses 0049_confirmation_functions.sql: the functions go.
-- Run it before the down of 0047.
BEGIN;

DO $$
BEGIN
    IF to_regprocedure('consentvault.confirmation_enqueue(uuid, text)') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0049 refused: 0049 is not applied';
    END IF;
END
$$;

DROP FUNCTION consentvault.confirmation_record_of(text);
DROP FUNCTION consentvault.confirmation_system_source(text);
DROP FUNCTION consentvault.confirmation_alarm_clear(text, timestamptz);
DROP FUNCTION consentvault.confirmation_alarm_raise(text, jsonb, timestamptz);
DROP FUNCTION consentvault.confirmation_wrapped_secret(text);
DROP FUNCTION consentvault.confirmation_account_secrets(uuid);
DROP FUNCTION consentvault.confirmation_work_orgs();
DROP FUNCTION consentvault.confirmation_org_ids();
DROP FUNCTION consentvault.confirmation_host_lookup(text);
DROP FUNCTION consentvault.confirmation_inbound_lookup(text);
DROP FUNCTION consentvault.confirmation_enqueue(uuid, text);

COMMIT;
