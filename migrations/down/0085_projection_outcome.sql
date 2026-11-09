-- Reverses 0085_projection_outcome.sql: the outcome table is dropped. A post whose only outcome was recorded there projects again
-- on the next run (the old fold's event link, not the outcome, decides whether an event exists).
BEGIN;
DROP TABLE consentvault.projection_outcome;
COMMIT;
