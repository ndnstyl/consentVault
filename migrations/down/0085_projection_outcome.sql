-- Reverses 0085_projection_outcome.sql. An outcome table holding rows is NEVER dropped: it is detached from the posts and renamed, so the
-- plain reason a post produced no event is not lost. (Writing them back as facts cannot be done here: a fact's value is encrypted under the
-- post's own key, which this role cannot use. The old fold is idempotent, so a post whose outcome is only in the kept table projects again
-- on the next run and reaches the same refusal; read the kept table to compare.) An empty table is dropped, so a down on an empty vault
-- leaves nothing behind.
BEGIN;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM consentvault.projection_outcome) THEN
        ALTER TABLE consentvault.projection_outcome DROP CONSTRAINT projection_outcome_org_id_post_id_fkey;
        ALTER TABLE consentvault.projection_outcome RENAME TO projection_outcome_kept_by_down;
    ELSE
        DROP TABLE consentvault.projection_outcome;
    END IF;
END;
$$;
COMMIT;
