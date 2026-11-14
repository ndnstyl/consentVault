-- A push's attempt time is the moment that push starts, not the moment its batch was claimed. The claim stamps last_attempt_at for
-- every row of a batch at once; a batch's later pushes start after the earlier ones finish, so their retry delay (counted from the
-- attempt) came out short by the time the earlier pushes took. The worker and the Twenty connector now stamp each row, through this
-- function, when its own push starts, and count the backoff from that stamp. The stamp is the database's clock, and the function answers it, so the caller counts the backoff from the same instant. Only the open attempt is stamped: a row taken over by
-- another worker or already finished is refused by name.

CREATE FUNCTION consentvault.sync_attempt_started(p_outbox_ids uuid[], p_attempts integer[]) RETURNS timestamptz
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.sync_org(ARRAY['worker:sync']);
    n   integer;
    t   timestamptz := clock_timestamp();   -- the database's clock, never the caller's; answered so the caller counts from it
BEGIN
    IF p_outbox_ids IS NULL OR p_attempts IS NULL OR cardinality(p_outbox_ids) <> cardinality(p_attempts)
       OR cardinality(p_outbox_ids) = 0 THEN
        RAISE EXCEPTION 'consentvault sync: a push start needs its time and one attempt per row' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE consentvault.outbox o SET last_attempt_at = t
      FROM unnest(p_outbox_ids, p_attempts) AS a(oid, att)
     WHERE o.org_id = org AND o.outbox_id = a.oid AND o.status = 'sent' AND o.attempts = a.att;
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n <> cardinality(p_outbox_ids) THEN
        RAISE EXCEPTION 'consentvault sync: a push started on an attempt that is no longer open' USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    RETURN t;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sync_attempt_started(uuid[], integer[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.sync_attempt_started(uuid[], integer[]) TO consentvault_worker;
