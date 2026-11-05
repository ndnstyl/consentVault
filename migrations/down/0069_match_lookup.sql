-- Reverses 0069_match_lookup.sql: the match writer's read function goes. It holds no data, so nothing is refused.
BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                   WHERE n.nspname = 'consentvault' AND p.proname = 'match_lookup') THEN
        RAISE EXCEPTION 'consentvault down 0069 refused: 0069 is not applied';
    END IF;
END
$$;

DROP FUNCTION consentvault.match_lookup(text);

COMMIT;
