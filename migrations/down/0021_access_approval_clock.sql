-- Reverses 0021_access_approval_clock.sql: approve_operator_access goes back to its 0017 shape. Run it as a superuser.
BEGIN;
CREATE OR REPLACE FUNCTION consentvault.approve_operator_access(p_operator_id text, p_reason text, p_access_minutes integer)
    RETURNS TABLE (approval_id uuid, expires_at timestamptz, approved_by uuid)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c   record;
    mid uuid;
    r   text;
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
    INSERT INTO consentvault.operator_access_approval (org_id, operator_id, reason, approved_by, expires_at, access_minutes)
    VALUES (c.org_id, p_operator_id, p_reason, mid, clock_timestamp() + interval '24 hours', p_access_minutes)
    RETURNING approval_id, expires_at, approved_by;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.approve_operator_access(text, text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.approve_operator_access(text, text, integer) TO consentvault_app;
COMMIT;
