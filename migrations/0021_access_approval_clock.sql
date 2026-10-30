-- An operator access approval reads the clock once.
--
-- 0017's approve_operator_access inserted expires_at as clock_timestamp() + 24 hours while approved_at took its own
-- default, clock_timestamp(), in the same row. Each call reads the clock again: approved_at (an earlier column) was read
-- first, expires_at a few microseconds later, so expires_at landed past approved_at + 24 hours whenever the two reads
-- fell in different microseconds, and the window check (expires_at <= approved_at + 24 hours) refused an admin's valid
-- approval. Here both times come from one reading.
CREATE OR REPLACE FUNCTION consentvault.approve_operator_access(p_operator_id text, p_reason text, p_access_minutes integer)
    RETURNS TABLE (approval_id uuid, expires_at timestamptz, approved_by uuid)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c   record;
    mid uuid;
    r   text;
    t0  timestamptz := clock_timestamp();
BEGIN
    SELECT * INTO c FROM consentvault.current_token_claims();
    IF NOT FOUND OR c.org_id IS NULL OR c.org_id IS DISTINCT FROM consentvault.current_org()
       OR c.credential_id IS NULL OR left(c.credential_id, 7) <> 'member:' THEN
        RAISE EXCEPTION 'consentvault operator access approval refused: no portal member session is entered'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    BEGIN
        mid := substr(c.credential_id, 8)::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'consentvault operator access approval refused: the session names no member'
            USING ERRCODE = 'insufficient_privilege';
    END;
    SELECT m.role INTO r FROM consentvault.member m WHERE m.org_id = c.org_id AND m.member_id = mid;
    IF r IS DISTINCT FROM 'admin' OR NOT ('admin' = ANY (c.scopes)) THEN
        RAISE EXCEPTION 'consentvault operator access approval refused: the session is not an admin of the organization'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN QUERY
    INSERT INTO consentvault.operator_access_approval (org_id, operator_id, reason, approved_by, approved_at, expires_at,
                                                       access_minutes)
    VALUES (c.org_id, p_operator_id, p_reason, mid, t0, t0 + interval '24 hours', p_access_minutes)
    RETURNING approval_id, expires_at, approved_by;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.approve_operator_access(text, text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.approve_operator_access(text, text, integer) TO consentvault_app;
