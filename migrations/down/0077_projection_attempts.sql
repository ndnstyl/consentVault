-- Reverses 0077_projection_attempts.sql: the recorded attempts on stored posts are dropped; no post, event or outcome fact is
-- touched. The halt behind a faulted post then has no first attempt to count from.
BEGIN;
DROP TABLE consentvault.projection_attempt;
COMMIT;
