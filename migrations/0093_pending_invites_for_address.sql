-- Pre-tenant: the open invitations addressed to one verified email. Lets a sign-in join the person to the organisations that
-- invited them without the emailed link. Answers ids, role and status only (the same columns as invite_lookup, no token
-- digest, no names); a withdrawn, accepted or expired invitation and a closed organisation are never returned.
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
CREATE FUNCTION consentvault.invite_pending_for_email(p_email_norm text)
    RETURNS TABLE (org_id uuid, invite_id uuid, role text, expires_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT i.org_id, i.invite_id, i.role, i.expires_at
    FROM consentvault.invite i
    JOIN consentvault.organization o ON o.org_id = i.org_id
    WHERE p_email_norm IS NOT NULL AND length(p_email_norm) BETWEEN 3 AND 320 AND i.email_norm = p_email_norm
      AND i.accepted_at IS NULL AND i.withdrawn_at IS NULL AND i.expires_at > clock_timestamp() AND o.status <> 'closed'
    ORDER BY i.org_id, i.invite_id;
$$;
ALTER FUNCTION consentvault.invite_pending_for_email(text) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.invite_pending_for_email(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.invite_pending_for_email(text) TO consentvault_app;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
