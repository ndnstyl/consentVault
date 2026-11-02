-- Reverses 0022_key_retention.sql. Run it as a superuser, in one transaction. A version held for the ledger reads as
-- retired again (its destroy_after stays as a record of the date).
BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'consentvault'
                    AND table_name = 'org_key' AND column_name = 'pre_schedule_status') THEN
        RAISE EXCEPTION 'consentvault down 0022 refused: 0022 is not applied';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION consentvault.org_key_version_guard() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    left_over text;
BEGIN
    IF OLD.status = 'retired' AND NEW.status = 'destroyed' THEN
        IF consentvault.current_org() IS DISTINCT FROM NEW.org_id THEN
            RAISE EXCEPTION 'consentvault.org_key: a key version is destroyed only inside its own organization'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        SELECT string_agg(c.kind || '=' || c.n, ', ') INTO left_over
          FROM consentvault.key_version_census_of(NEW.org_id, NEW.version) c WHERE c.n > 0;
        IF left_over IS NOT NULL THEN
            RAISE EXCEPTION 'key_version_in_use: version % still wraps %', NEW.version, left_over
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    IF OLD.status = 'destroyed' AND NEW.status IS DISTINCT FROM 'destroyed' THEN
        RAISE EXCEPTION 'consentvault.org_key: a destroyed key version stays destroyed' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

UPDATE consentvault.org_key SET status = 'retired' WHERE status = 'retained_for_ledger';
ALTER TABLE consentvault.org_key DROP CONSTRAINT org_key_retained_shape;
ALTER TABLE consentvault.org_key DROP COLUMN pre_schedule_destroy_after, DROP COLUMN pre_schedule_status;
ALTER TABLE consentvault.org_key DROP CONSTRAINT org_key_status_check;
ALTER TABLE consentvault.org_key ADD CONSTRAINT org_key_status_check
    CHECK (status IN ('active', 'retired', 'scheduled_destroy', 'destroyed'));

COMMIT;
