-- The Twenty workflow credential (contract twenty.md 4.2): the one credential a Twenty workflow holds to ask POST /v1/permission
-- before it sends an email. Scope gate_check: that one route and nothing else. One per connected Twenty system, issued by an
-- admin only and only once an approved policy is in force; an opaque secret shown once and stored only as its SHA-256; 90 days,
-- a replacement from day 76 with both working for 14 days, then the old one stops; revocable at once; 60 checks a minute;
-- reminders to the organisation's admins at 14 and 3 days before expiry. Every span is written in hours (90 days = 2160 hours,
-- day 76 = 1824 hours, 14 days = 336 hours, 3 days = 72 hours): a day interval moves with the session's time zone across a
-- daylight-saving change, an hour interval does not. Every check is a gate_decision whose requested_by is
-- the credential's id, so the proof shows which system asked.

CREATE TABLE consentvault.workflow_credential (
    org_id        uuid NOT NULL REFERENCES consentvault.organization (org_id),
    credential_id uuid NOT NULL DEFAULT gen_random_uuid(),
    system_id     uuid NOT NULL,
    secret_hash   text NOT NULL UNIQUE CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
    created_by    text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 200),
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    overlap_until timestamptz,
    revoked_at    timestamptz,
    tokens        double precision NOT NULL DEFAULT 60 CHECK (tokens >= 0),
    refilled_at   timestamptz NOT NULL,
    reminded_14   timestamptz,
    reminded_3    timestamptz,
    PRIMARY KEY (org_id, credential_id),
    FOREIGN KEY (org_id, system_id) REFERENCES consentvault.connected_system (org_id, system_id),
    CONSTRAINT workflow_credential_lifetime CHECK (expires_at = created_at + interval '2160 hours')
);
CREATE INDEX workflow_credential_system_idx ON consentvault.workflow_credential (org_id, system_id, created_at DESC);
-- One current credential per system, held by the database whatever the caller does: the current one is the credential not revoked
-- and not yet replaced (a replaced one carries overlap_until; an issue closes an ended one the same way before it adds the next).
CREATE UNIQUE INDEX workflow_credential_one_current ON consentvault.workflow_credential (org_id, system_id)
    WHERE revoked_at IS NULL AND overlap_until IS NULL;
ALTER TABLE consentvault.workflow_credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.workflow_credential FORCE ROW LEVEL SECURITY;
CREATE POLICY workflow_credential_tenant ON consentvault.workflow_credential
    USING (org_id = (SELECT consentvault.current_org())) WITH CHECK (org_id = (SELECT consentvault.current_org()));
REVOKE ALL ON consentvault.workflow_credential FROM PUBLIC;
-- the check resolves the secret before any tenant is entered (as resolve_site_key does): the operator role owns that one function
GRANT SELECT (org_id, credential_id, system_id, secret_hash, expires_at, overlap_until, revoked_at, tokens, refilled_at),
    UPDATE (tokens, refilled_at) ON consentvault.workflow_credential TO consentvault_operator;

-- When a credential stops working: its expiry, or the end of its overlap once a replacement exists.
CREATE FUNCTION consentvault.workflow_credential_end(p_expires timestamptz, p_overlap timestamptz) RETURNS timestamptz
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN p_overlap IS NULL THEN p_expires ELSE least(p_expires, p_overlap) END;
$$;

-- Issue (admin only), on the database's clock. No live credential: a new one. One live credential and none overlapping it: a replacement, allowed from day
-- 76 (14 days before its expiry); the old one then works 14 more days. Each refusal has its own SQLSTATE: CVW01 no policy in
-- force, CVW02 the system is disconnected, CVW03 a replacement before day 76 (or a second one). The system row is held FOR NO KEY
-- UPDATE to the end of the transaction: a disconnect (which updates that row) waits for this issue and then revokes what it made,
-- an issue that waited on a disconnect sees the status it left, and two issues on one system run one after the other, so the
-- second counts the first's credential. The unique index workflow_credential_one_current holds the same rule underneath.
CREATE FUNCTION consentvault.workflow_credential_issue(p_system_id uuid, p_secret_hash text, p_created_by text)
    RETURNS TABLE (credential_id uuid, expires_at timestamptz, replaced uuid)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org  uuid := consentvault.connector_org(p_system_id, ARRAY['admin'], false);
    t_now timestamptz := clock_timestamp();   -- the database's clock: no caller names a credential's lifetime
    st   text;
    live record;
    n    integer;
    new_id uuid := gen_random_uuid();
BEGIN
    SELECT s.status INTO st FROM consentvault.connected_system s
     WHERE s.org_id = org AND s.system_id = p_system_id FOR NO KEY UPDATE;
    IF st = 'disconnected' THEN
        RAISE EXCEPTION 'system_disconnected: the system is disconnected, so no gate credential is issued' USING ERRCODE = 'CVW02';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM consentvault.policy p WHERE p.org_id = org AND p.status = 'approved') THEN
        RAISE EXCEPTION 'policy_required: no approved policy is in force, so no gate credential is issued'
            USING ERRCODE = 'CVW01';
    END IF;
    SELECT count(*) INTO n FROM consentvault.workflow_credential w
     WHERE w.org_id = org AND w.system_id = p_system_id AND w.revoked_at IS NULL
       AND consentvault.workflow_credential_end(w.expires_at, w.overlap_until) > t_now;
    SELECT w.credential_id AS id, w.created_at AS created, w.overlap_until AS overlap INTO live
      FROM consentvault.workflow_credential w
     WHERE w.org_id = org AND w.system_id = p_system_id AND w.revoked_at IS NULL
       AND consentvault.workflow_credential_end(w.expires_at, w.overlap_until) > t_now
     ORDER BY w.created_at LIMIT 1 FOR UPDATE;
    IF n > 1 OR (n = 1 AND (live.overlap IS NOT NULL OR t_now < live.created + interval '1824 hours')) THEN
        RAISE EXCEPTION 'replacement refused: one gate credential per system; a replacement may be made from day 76 of the current one'
            USING ERRCODE = 'CVW03';
    END IF;
    IF n = 1 THEN
        UPDATE consentvault.workflow_credential w SET overlap_until = t_now + interval '336 hours'
         WHERE w.org_id = org AND w.credential_id = live.id;
    END IF;
    -- a credential that ended without a replacement is closed at its expiry (its end does not move), so it is not current
    UPDATE consentvault.workflow_credential w SET overlap_until = w.expires_at
     WHERE w.org_id = org AND w.system_id = p_system_id AND w.revoked_at IS NULL AND w.overlap_until IS NULL
       AND w.expires_at <= t_now;
    BEGIN
        INSERT INTO consentvault.workflow_credential (org_id, credential_id, system_id, secret_hash, created_by, created_at,
                                                      expires_at, refilled_at)
        VALUES (org, new_id, p_system_id, p_secret_hash, p_created_by, t_now, t_now + interval '2160 hours', t_now);
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'replacement refused: the system already has a current gate credential' USING ERRCODE = 'CVW03';
    END;
    credential_id := new_id; expires_at := t_now + interval '2160 hours'; replaced := CASE WHEN n = 1 THEN live.id END;
    RETURN NEXT;
END;
$$;

-- Revoke (admin only): the system's credential stops at once. False when no unrevoked credential of that id belongs to the system.
CREATE FUNCTION consentvault.workflow_credential_revoke(p_system_id uuid, p_credential_id uuid)
    RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.connector_org(p_system_id, ARRAY['admin'], false);
    n   integer;
BEGIN
    UPDATE consentvault.workflow_credential SET revoked_at = clock_timestamp()
     WHERE org_id = org AND system_id = p_system_id AND credential_id = p_credential_id AND revoked_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n = 1;
END;
$$;

-- A disconnect revokes the system's credentials in the same transaction, whichever path set the status (twenty.md 5.2).
CREATE FUNCTION consentvault.workflow_credential_disconnect() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE consentvault.workflow_credential SET revoked_at = clock_timestamp()
     WHERE org_id = NEW.org_id AND system_id = NEW.system_id AND revoked_at IS NULL;
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.workflow_credential_disconnect() FROM PUBLIC;
CREATE TRIGGER workflow_credential_disconnect AFTER UPDATE OF status ON consentvault.connected_system
    FOR EACH ROW WHEN (NEW.status = 'disconnected' AND OLD.status IS DISTINCT FROM 'disconnected')
    EXECUTE FUNCTION consentvault.workflow_credential_disconnect();

-- One check's use of a credential, on the database's clock and at the contract's 60 a minute, before any tenant is entered: resolve the secret by its hash, refuse a revoked or ended one by
-- name, refuse one whose system is disconnected (a backstop to the revoke the disconnect makes), and take one token from its
-- bucket (p_per_minute a minute). Owned by the operator role.
CREATE FUNCTION consentvault.workflow_credential_use(p_secret_hash text)
    RETURNS TABLE (org_id uuid, credential_id uuid, system_id uuid, outcome text, retry_after integer)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    w record;
    t double precision;
    p_now        timestamptz := clock_timestamp();   -- the database's clock: no caller can make an ended credential pass
    p_per_minute constant integer := 60;             -- the contract's rate (twenty.md 4.2); no caller can raise it
BEGIN
    SELECT c.org_id AS org, c.credential_id AS id, c.system_id AS sys, c.revoked_at AS revoked,
           consentvault.workflow_credential_end(c.expires_at, c.overlap_until) AS ends, c.tokens AS tokens,
           c.refilled_at AS at
      INTO w FROM consentvault.workflow_credential c
     WHERE p_secret_hash ~ '^[0-9a-f]{64}$' AND c.secret_hash = p_secret_hash FOR UPDATE;
    IF NOT FOUND THEN
        org_id := NULL; credential_id := NULL; system_id := NULL; outcome := 'unknown'; retry_after := NULL;
        RETURN NEXT; RETURN;
    END IF;
    org_id := w.org; credential_id := w.id; system_id := w.sys; retry_after := NULL;
    IF w.revoked IS NOT NULL THEN
        outcome := 'revoked'; RETURN NEXT; RETURN;
    END IF;
    IF p_now >= w.ends THEN
        outcome := 'expired'; RETURN NEXT; RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM consentvault.connected_system s
                    WHERE s.org_id = w.org AND s.system_id = w.sys AND s.status <> 'disconnected') THEN
        outcome := 'disconnected'; RETURN NEXT; RETURN;
    END IF;
    t := least(p_per_minute::double precision, w.tokens + greatest(0, extract(epoch FROM (p_now - w.at))) * p_per_minute / 60.0);
    IF t < 1 THEN
        UPDATE consentvault.workflow_credential c SET tokens = t, refilled_at = greatest(w.at, p_now)
         WHERE c.org_id = w.org AND c.credential_id = w.id;
        outcome := 'rate_limited'; retry_after := greatest(1, ceil((1 - t) * 60.0 / p_per_minute))::integer;
        RETURN NEXT; RETURN;
    END IF;
    UPDATE consentvault.workflow_credential c SET tokens = t - 1, refilled_at = greatest(w.at, p_now)
     WHERE c.org_id = w.org AND c.credential_id = w.id;
    outcome := 'ok';
    RETURN NEXT;
END;
$$;

-- The reminders due now (admin, or the reminder job under a worker token): a live credential 14 days or fewer from its end,
-- and again 3 days or fewer; each once. "Now" is the database's clock, never the caller's: a caller that could name the time could
-- mark every reminder sent ahead of its day. Each row carries the organisation's name and its admins' addresses, read only for a
-- reminder that is due, so the job can email them; the caller sends inside this transaction, so a failed send leaves it due.
CREATE FUNCTION consentvault.workflow_credential_reminders_due()
    RETURNS TABLE (credential_id uuid, system_id uuid, days_left integer, ends_at timestamptz, company text,
                   admin_emails text[])
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org   uuid := consentvault.sync_org(ARRAY['admin', 'worker:sync']);
    t_now timestamptz := clock_timestamp();
BEGIN
    RETURN QUERY
    WITH due AS (
        UPDATE consentvault.workflow_credential c
           SET reminded_3 = CASE WHEN c.expires_at - interval '72 hours' <= t_now THEN t_now ELSE c.reminded_3 END,
               reminded_14 = coalesce(c.reminded_14, t_now)
         WHERE c.org_id = org AND c.revoked_at IS NULL AND c.overlap_until IS NULL AND t_now < c.expires_at
           AND ((c.expires_at - interval '336 hours' <= t_now AND c.reminded_14 IS NULL)
                OR (c.expires_at - interval '72 hours' <= t_now AND c.reminded_3 IS NULL))
        RETURNING c.credential_id, c.system_id, c.expires_at
    )
    SELECT d.credential_id, d.system_id,
           CASE WHEN d.expires_at - interval '72 hours' <= t_now THEN 3 ELSE 14 END, d.expires_at,
           (SELECT o.name FROM consentvault.organization o WHERE o.org_id = org),
           ARRAY(SELECT m.email_norm FROM consentvault.member m
                  WHERE m.org_id = org AND m.role = 'admin' AND m.email_norm IS NOT NULL ORDER BY m.email_norm)
      FROM due d ORDER BY d.expires_at;
END;
$$;

GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
ALTER FUNCTION consentvault.workflow_credential_use(text) OWNER TO consentvault_operator;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.workflow_credential_end(timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.workflow_credential_end(timestamptz, timestamptz) TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.workflow_credential_issue(uuid, text, text),
    consentvault.workflow_credential_revoke(uuid, uuid), consentvault.workflow_credential_use(text),
    consentvault.workflow_credential_reminders_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.workflow_credential_issue(uuid, text, text),
    consentvault.workflow_credential_revoke(uuid, uuid), consentvault.workflow_credential_use(text),
    consentvault.workflow_credential_reminders_due() TO consentvault_app;
GRANT EXECUTE ON FUNCTION consentvault.workflow_credential_reminders_due() TO consentvault_worker;
