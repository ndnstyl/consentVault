-- Reverses 0007_billing.sql. Refuses while the vault holds what the older schema cannot: an organisation in the trial
-- or past_due status, or any Stripe link, webhook event or usage count (billing records are evidence of what was
-- charged and reported; a down migration never destroys them).
--
-- Run it as a superuser (or a BYPASSRLS role), in one transaction. Row security is switched off for the transaction so
-- a filtered role gets an error instead of counting zero rows.
BEGIN;
SET LOCAL row_security = off;

DO $$
BEGIN
    IF to_regclass('consentvault.billing_account') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0007 refused: consentvault.billing_account is missing; 0007 is not applied';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.organization WHERE status IN ('trial', 'past_due')) THEN
        RAISE EXCEPTION 'consentvault down 0007 refused: an organisation is in trial or past_due; move it to a status the older schema holds first';
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.billing_account) OR EXISTS (SELECT 1 FROM consentvault.billing_event)
       OR EXISTS (SELECT 1 FROM consentvault.usage_day) THEN
        RAISE EXCEPTION 'consentvault down 0007 refused: billing accounts, webhook events or usage counts exist';
    END IF;
END
$$;

-- The three lookups return to their 0002 definitions (owner and shape unchanged).
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
CREATE OR REPLACE FUNCTION consentvault.resolve_credential(p_credential_id uuid)
    RETURNS TABLE (org_id uuid, scopes text[], public_key text, alg text, kind text, allowed_origins text[], status text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT c.org_id, c.scope, c.public_key, c.alg, c.kind, coalesce(s.allowed_origins, '{}'::text[]),
           CASE WHEN c.revoked_at IS NOT NULL THEN 'revoked'
                WHEN o.status <> 'active' THEN 'org_' || o.status
                ELSE 'active' END
    FROM consentvault.credential c
    JOIN consentvault.organization o ON o.org_id = c.org_id
    LEFT JOIN consentvault.capture_source s ON s.org_id = c.org_id AND s.source_id = c.source_id
    WHERE c.credential_id = p_credential_id;
$$;
CREATE OR REPLACE FUNCTION consentvault.resolve_member(p_idp_issuer text, p_idp_subject text)
    RETURNS TABLE (org_id uuid, role text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT m.org_id, m.role
    FROM consentvault.member m
    JOIN consentvault.organization o ON o.org_id = m.org_id
    WHERE m.idp_issuer = p_idp_issuer AND m.idp_subject = p_idp_subject AND o.status = 'active'
    ORDER BY m.org_id;
$$;
CREATE OR REPLACE FUNCTION consentvault.active_org_ids() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT org_id FROM consentvault.organization WHERE status = 'active' ORDER BY org_id;
$$;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;

DROP FUNCTION consentvault.usage_mark_reported(date, text, text);
DROP FUNCTION consentvault.usage_target(date);
DROP FUNCTION consentvault.usage_record_day(date, bigint, bigint);
DROP FUNCTION consentvault.usage_events_for_day(date);
DROP FUNCTION consentvault.usage_require_scope();
DROP FUNCTION consentvault.billing_apply_status(uuid, text, text, text, text[]);
-- the twelve-argument form 0041 added (a vault that has not run down/0041 first)
DROP FUNCTION IF EXISTS consentvault.billing_link_account(uuid, text, text, text, text, text, text, bigint, bigint,
    timestamptz, timestamptz, text);
DROP FUNCTION IF EXISTS consentvault.billing_link_account(uuid, text, text, text, text, text, text, bigint, bigint,
    timestamptz, timestamptz);
DROP FUNCTION consentvault.billing_event_outcomes();
DROP FUNCTION consentvault.billing_finish_event(text, uuid, text);
DROP FUNCTION consentvault.billing_record_event(text, text);
DROP FUNCTION consentvault.billing_resolve_org(text, uuid);
DROP TRIGGER organization_status_history ON consentvault.organization;
DROP FUNCTION consentvault.org_status_history_log();
DROP TABLE consentvault.usage_day;
DROP TABLE consentvault.billing_event;
DROP TABLE consentvault.billing_account;
-- The history is derived (the status in force) and the trigger that wrote it is gone, so it goes with the migration.
ALTER TABLE consentvault.org_status_history DISABLE TRIGGER org_status_history_append_only;
DROP TABLE consentvault.org_status_history;

REVOKE SELECT (org_id, status, created_at) ON consentvault.organization FROM consentvault_operator;
GRANT SELECT (org_id, status) ON consentvault.organization TO consentvault_operator;
ALTER TABLE consentvault.organization DROP CONSTRAINT organization_status_check;
ALTER TABLE consentvault.organization ADD CONSTRAINT organization_status_check
    CHECK (status IN ('active', 'suspended', 'offboarding', 'closed'));
COMMIT;
