-- Key versions kept for the lifecycle ledger, and an offboarding hold that gives back only what it took.
--
-- 1. A retired key version that still seals a write-once lifecycle ledger entry (a hold's reason, kept in the archive
--    under Object Lock) inside that entry's retention is not destroyed by a rotation. It is held as
--    'retained_for_ledger', destroy_after set to the end of the last such entry's retention, and destroyed by the key
--    rotation job once that time has passed. Offboarding is unchanged: it destroys every version.
-- 2. Offboarding remembers what each version was before it scheduled the destruction (pre_schedule_status,
--    pre_schedule_destroy_after). A hold that cancels the destruction puts each version back as it was: an active version
--    returns to active, a version a rotation retired or retained stays so.
ALTER TABLE consentvault.org_key DROP CONSTRAINT org_key_status_check;
ALTER TABLE consentvault.org_key ADD CONSTRAINT org_key_status_check
    CHECK (status IN ('active', 'retired', 'retained_for_ledger', 'scheduled_destroy', 'destroyed'));
ALTER TABLE consentvault.org_key
    ADD COLUMN pre_schedule_status text
        CHECK (pre_schedule_status IS NULL OR pre_schedule_status IN ('active', 'retired', 'retained_for_ledger')),
    ADD COLUMN pre_schedule_destroy_after timestamptz;
ALTER TABLE consentvault.org_key ADD CONSTRAINT org_key_retained_shape
    CHECK (status <> 'retained_for_ledger' OR destroy_after IS NOT NULL);

-- The 0020 guard, extended: a version is retained or destroyed after a rotation only when nothing is wrapped under it.
CREATE OR REPLACE FUNCTION consentvault.org_key_version_guard() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    left_over text;
BEGIN
    IF OLD.status IN ('retired', 'retained_for_ledger') AND NEW.status IN ('retained_for_ledger', 'destroyed')
       AND NEW.status IS DISTINCT FROM OLD.status THEN
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
