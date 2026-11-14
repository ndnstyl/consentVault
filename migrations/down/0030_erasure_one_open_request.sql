-- Reverses 0030_erasure_one_open_request.sql: a contact may again have more than one open erasure request.
BEGIN;
DROP INDEX IF EXISTS consentvault.erasure_request_one_open_idx;
COMMIT;
