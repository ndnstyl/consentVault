-- Reverses 0012_suspension_reason.sql: the webhook status function as 0007 wrote it, and the reason column goes.
-- Run it as a superuser (or a BYPASSRLS role), in one transaction.
BEGIN;

DO $$
BEGIN
    IF to_regprocedure('consentvault.organization_suspension_reason()') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0012 refused: 0012 is not applied';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION consentvault.billing_apply_status(
    p_org uuid, p_to text, p_cause text, p_event_id text, p_only_from text[] DEFAULT NULL) RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    prev   text := pg_catalog.current_setting('consentvault.org_token', true);
    cur    text;
    legal  boolean;
BEGIN
    IF NOT ((p_cause = 'invoice_paid' AND p_to = 'active') OR (p_cause = 'payment_failed' AND p_to = 'past_due')
            OR (p_cause = 'subscription_deleted' AND p_to = 'suspended')) THEN
        RAISE EXCEPTION 'consentvault billing: cause % cannot lead to status %', p_cause, p_to
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_event_id IS NULL OR p_event_id !~ '^evt_[A-Za-z0-9_]{1,100}$' THEN
        RAISE EXCEPTION 'consentvault billing: a webhook status change must name its Stripe event'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_catalog.set_config('consentvault.org_token',
                                  consentvault.sign_org_token(p_org, ARRAY['billing'], NULL, 60), true);
    SELECT status INTO cur FROM consentvault.organization WHERE org_id = p_org FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault billing: organisation % does not exist', p_org USING ERRCODE = 'no_data_found';
    END IF;
    IF cur IN ('offboarding', 'closed') THEN
        PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
        RETURN 'refused_terminal';
    END IF;
    IF cur = p_to OR (p_only_from IS NOT NULL AND cur <> ALL (p_only_from)) THEN
        PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
        RETURN 'unchanged';
    END IF;
    legal := (p_to = 'active' AND cur IN ('trial', 'past_due', 'suspended'))
          OR (p_to = 'past_due' AND cur = 'active')
          OR (p_to = 'suspended' AND cur IN ('trial', 'active', 'past_due'));
    IF NOT legal THEN
        PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
        RETURN 'refused_transition';
    END IF;
    PERFORM pg_catalog.set_config('consentvault.status_cause', p_cause, true);
    PERFORM pg_catalog.set_config('consentvault.status_actor', 'stripe:' || p_event_id, true);
    UPDATE consentvault.organization SET status = p_to WHERE org_id = p_org;
    PERFORM pg_catalog.set_config('consentvault.status_cause', '', true);
    PERFORM pg_catalog.set_config('consentvault.status_actor', '', true);
    PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prev, ''), true);
    RETURN 'changed';
END;
$$;
DROP TRIGGER organization_suspension_reason ON consentvault.organization;
DROP FUNCTION consentvault.organization_suspension_reason();
ALTER TABLE consentvault.organization DROP CONSTRAINT organization_suspension_reason_only_when_suspended;
ALTER TABLE consentvault.organization DROP COLUMN suspension_reason;

COMMIT;
