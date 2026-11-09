-- Wording versions: the link to the version a new one replaces is checked by the database as the row is written.
-- The disclosure table is already append-only (the link can never be edited) and one version can be replaced once
-- (disclosure_one_successor_idx). This adds what the API alone enforced or did not: the replaced version exists in the
-- SAME organisation, is not the row itself, no chain loops back, and the new version starts after the one it replaces.
CREATE FUNCTION consentvault.disclosure_replaces_guard() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    target  consentvault.disclosure%ROWTYPE;
    cur     text;
    hops    integer := 0;
BEGIN
    IF NEW.supersedes_sha256 IS NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.supersedes_sha256 = NEW.sha256 THEN
        RAISE EXCEPTION 'consentvault.disclosure: a wording cannot replace itself' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    SELECT * INTO target FROM consentvault.disclosure d WHERE d.org_id = NEW.org_id AND d.sha256 = NEW.supersedes_sha256;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault.disclosure: the wording it replaces is not held by this organisation'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.effective_from IS NOT NULL AND target.effective_from IS NOT NULL AND NEW.effective_from <= target.effective_from THEN
        RAISE EXCEPTION 'consentvault.disclosure: a replacing wording must start after the one it replaces'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    cur := target.supersedes_sha256;
    WHILE cur IS NOT NULL LOOP
        IF cur = NEW.sha256 THEN
            RAISE EXCEPTION 'consentvault.disclosure: a replacement chain cannot loop back' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        hops := hops + 1;
        IF hops > 10000 THEN
            RAISE EXCEPTION 'consentvault.disclosure: replacement chain too long to check' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        SELECT d.supersedes_sha256 INTO cur FROM consentvault.disclosure d WHERE d.org_id = NEW.org_id AND d.sha256 = cur;
    END LOOP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER disclosure_replaces_guard BEFORE INSERT ON consentvault.disclosure
    FOR EACH ROW EXECUTE FUNCTION consentvault.disclosure_replaces_guard();
