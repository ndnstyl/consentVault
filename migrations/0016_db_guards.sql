-- Database guards after the third adversarial review.
--
-- 1. Hold releases. The tenant runtime role no longer writes a hold's release columns. A release goes through one of two
--    functions that run with the owner's rights and name the actor themselves:
--      * release_hold_as_member: the actor is the member the verified tenant token names (an admin of the entered
--        organisation, holding exactly the admin scopes). A hold set for legal process is refused here.
--      * release_hold_as_operator: executable by the owner only, which is the operator's session. The app never holds it.
-- 2. Request rows start where a request starts. The tenant runtime role may insert only the request columns of an
--    erasure or offboarding request, and a trigger refuses, for every role, a new row already past its first state: an
--    erasure confirmed, declined, completed or held; an offboarding in progress, with steps, a destruction date or a
--    final export.
--
-- Ownership and roles are not changed here.

-- 1. Hold releases ------------------------------------------------------------------------------------------------------
REVOKE UPDATE (released_by_kind, released_by, released_at, release_reason, release_ledger_seq)
    ON consentvault.legal_hold FROM consentvault_app;
REVOKE UPDATE ON consentvault.legal_hold FROM consentvault_app;

-- Shared body: the release itself, for an actor already established by the caller function.
CREATE FUNCTION consentvault.release_hold_row(p_org uuid, p_hold uuid, p_kind text, p_actor text, p_reason text,
                                              p_released_at timestamptz, p_ledger_seq bigint) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    h record;
BEGIN
    IF p_released_at IS NULL OR p_released_at > clock_timestamp() + interval '1 minute'
       OR p_released_at < clock_timestamp() - interval '10 minutes' THEN
        RAISE EXCEPTION 'consentvault hold release refused: the release time must be now (got %)', p_released_at
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT set_by_kind, released_at INTO h FROM consentvault.legal_hold
     WHERE org_id = p_org AND hold_id = p_hold FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault hold release refused: no hold % in the entered organization', p_hold
            USING ERRCODE = 'no_data_found';
    END IF;
    IF h.released_at IS NOT NULL THEN
        RAISE EXCEPTION 'consentvault hold release refused: hold % is already released', p_hold
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF h.set_by_kind = 'operator' AND p_kind <> 'operator' THEN
        RAISE EXCEPTION 'consentvault hold release refused: a hold set for legal process is released only by the operator'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    UPDATE consentvault.legal_hold
       SET released_by_kind = p_kind, released_by = p_actor, released_at = p_released_at,
           release_reason = p_reason, release_ledger_seq = p_ledger_seq
     WHERE org_id = p_org AND hold_id = p_hold;
    RETURN p_hold;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.release_hold_row(uuid, uuid, text, text, text, timestamptz, bigint) FROM PUBLIC;

-- A client admin's release. The actor is read from the verified tenant token, never from the caller. p_expected_actor
-- is a cross-check only (the ledger entry the caller already wrote names it): a mismatch refuses.
CREATE FUNCTION consentvault.release_hold_as_member(p_hold uuid, p_reason text, p_released_at timestamptz,
                                                    p_ledger_seq bigint, p_expected_actor text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c   record;
    mid uuid;
    r   text;
BEGIN
    SELECT * INTO c FROM consentvault.current_token_claims();
    IF NOT FOUND OR c.org_id IS NULL OR c.org_id IS DISTINCT FROM consentvault.current_org()
       OR c.credential_id IS NULL OR left(c.credential_id, 7) <> 'member:' THEN
        RAISE EXCEPTION 'consentvault hold release refused: no portal member session is entered'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    BEGIN
        mid := substr(c.credential_id, 8)::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'consentvault hold release refused: the session names no member'
            USING ERRCODE = 'insufficient_privilege';
    END;
    SELECT role INTO r FROM consentvault.member WHERE org_id = c.org_id AND member_id = mid;
    IF r IS DISTINCT FROM 'admin' OR c.scopes IS DISTINCT FROM ARRAY['admin']::text[] THEN
        RAISE EXCEPTION 'consentvault hold release refused: the session is not an admin of the organization'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_expected_actor IS NOT NULL AND p_expected_actor <> mid::text THEN
        RAISE EXCEPTION 'consentvault hold release refused: the named actor does not match the session member'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN consentvault.release_hold_row(c.org_id, p_hold, 'member', mid::text, p_reason, p_released_at, p_ledger_seq);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.release_hold_as_member(uuid, text, timestamptz, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.release_hold_as_member(uuid, text, timestamptz, bigint, text) TO consentvault_app;

-- An operator's release, on the owner's own connection inside the entered organisation. Never granted to the app.
CREATE FUNCTION consentvault.release_hold_as_operator(p_hold uuid, p_reason text, p_released_at timestamptz,
                                                      p_ledger_seq bigint, p_operator_id text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.current_org();
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault hold release refused: no organization is entered'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_operator_id IS NULL OR length(p_operator_id) NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'consentvault hold release refused: the operator id is missing or malformed'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN consentvault.release_hold_row(org, p_hold, 'operator', p_operator_id, p_reason, p_released_at, p_ledger_seq);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.release_hold_as_operator(uuid, text, timestamptz, bigint, text) FROM PUBLIC;

-- 2. Request rows start where a request starts ---------------------------------------------------------------------------
REVOKE INSERT ON consentvault.erasure_request FROM consentvault_app;
GRANT INSERT (org_id, erasure_id, contact_fp, reason, requested_by) ON consentvault.erasure_request TO consentvault_app;
REVOKE INSERT ON consentvault.offboarding_request FROM consentvault_app;
GRANT INSERT (org_id, request_id, reason, requested_by) ON consentvault.offboarding_request TO consentvault_app;

CREATE FUNCTION consentvault.erasure_request_initial() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM 'pending_operator_confirmation'
       OR NEW.confirmed_by IS NOT NULL OR NEW.confirmed_at IS NOT NULL
       OR NEW.held_by IS NOT NULL OR NEW.held_since IS NOT NULL
       OR NEW.decline_reason IS NOT NULL OR NEW.completed_at IS NOT NULL
       OR NEW.ledger_seq IS NOT NULL OR NEW.ledger_sha256 IS NOT NULL THEN
        RAISE EXCEPTION 'consentvault.erasure_request: a new request starts in its first state (pending operator confirmation, nothing confirmed, held, declined or completed)'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER erasure_request_initial BEFORE INSERT ON consentvault.erasure_request
    FOR EACH ROW EXECUTE FUNCTION consentvault.erasure_request_initial();

CREATE FUNCTION consentvault.offboarding_request_initial() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.state IS DISTINCT FROM 'requested' OR NEW.steps IS DISTINCT FROM '{}'::jsonb
       OR NEW.destroy_after IS NOT NULL OR NEW.final_export_at IS NOT NULL OR NEW.final_export_sha256 IS NOT NULL
       OR NEW.final_export_key IS NOT NULL OR NEW.final_export_wrapped IS NOT NULL THEN
        RAISE EXCEPTION 'consentvault.offboarding_request: a new request starts in its first state (requested, no steps, no destruction date, no final export)'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER offboarding_request_initial BEFORE INSERT ON consentvault.offboarding_request
    FOR EACH ROW EXECUTE FUNCTION consentvault.offboarding_request_initial();
