-- Reverses 0083_reroute_is_an_intake_action.sql: the reroute table is dropped; the posts and facts it pointed between are untouched.
BEGIN;
DROP TABLE consentvault.raw_post_reroute;
COMMIT;
