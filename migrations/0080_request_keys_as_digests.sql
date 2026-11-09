-- A request key is stored and indexed as its sha256, never as the sender's text (one-door review round 4 and 5). Migrations 0073
-- to 0078 stored the key as sent, in the event link (request_key) and in raw_post_request. This rewrites every such row to the
-- digest the code now writes and looks up, so a copy of a request is still found by its key. Keys always carry a prefix
-- (sig:, id:, edge:, twilio:), so a stored value that is 64 lowercase hex characters is already a digest and is left alone: a
-- second run changes nothing.
--
-- Both tables are append-only, and the guard on the database refuses to switch a change trigger off. So their change guard
-- learns the one change this migration makes and no other: an update is allowed only when the request key is the single column
-- that changes and the new value is the sha256 of the old one. Any other update or delete is refused exactly as before.
CREATE OR REPLACE FUNCTION consentvault.refuse_change_except_key_digest() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.request_key IS NOT NULL AND OLD.request_key !~ '^[0-9a-f]{64}$'
       AND NEW.request_key = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(OLD.request_key, 'UTF8')), 'hex')
       AND (to_jsonb(NEW) - 'request_key') = (to_jsonb(OLD) - 'request_key') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'consentvault.% is append-only: % refused', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;
CREATE OR REPLACE TRIGGER event_source_post_append_only BEFORE UPDATE OR DELETE ON consentvault.event_source_post
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change_except_key_digest();
CREATE OR REPLACE TRIGGER raw_post_request_append_only BEFORE UPDATE OR DELETE ON consentvault.raw_post_request
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change_except_key_digest();

UPDATE consentvault.event_source_post
   SET request_key = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(request_key, 'UTF8')), 'hex')
 WHERE request_key IS NOT NULL AND request_key !~ '^[0-9a-f]{64}$';
UPDATE consentvault.raw_post_request
   SET request_key = pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(request_key, 'UTF8')), 'hex')
 WHERE request_key !~ '^[0-9a-f]{64}$';
