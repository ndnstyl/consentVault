-- Transactional email: the send log. Platform scope (no org_id, no row-level security): one row per send attempt or
-- bounce, carrying the template type, the recipient's domain only, the outcome, the provider and its message id. No
-- body, no subject, no full address. The runtime and worker roles append; nobody updates or deletes; the operator reads.

CREATE TABLE consentvault.notify_send_log (
    send_id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type                text NOT NULL CHECK (type IN ('invite', 'security_alert', 'delivery_failure', 'billing_notice')),
    recipient_domain    text NOT NULL CHECK (recipient_domain ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
                                             AND length(recipient_domain) <= 253),
    outcome             text NOT NULL CHECK (outcome IN ('sent', 'failed', 'bounced')),
    provider            text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_]{0,40}$'),
    provider_message_id text CHECK (length(provider_message_id) BETWEEN 1 AND 300),
    -- a short reason; never an address (the writer scrubs them, the check refuses any that slip through)
    detail              text CHECK (length(detail) BETWEEN 1 AND 200 AND position('@' IN detail) = 0),
    at                  timestamptz NOT NULL,
    recorded_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT notify_send_log_sent_has_id CHECK (outcome <> 'sent' OR provider_message_id IS NOT NULL)
);
CREATE INDEX notify_send_log_outcome_at_idx ON consentvault.notify_send_log (outcome, at);

CREATE TRIGGER notify_send_log_append_only BEFORE UPDATE OR DELETE ON consentvault.notify_send_log
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER notify_send_log_no_truncate BEFORE TRUNCATE ON consentvault.notify_send_log
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

REVOKE ALL ON consentvault.notify_send_log FROM PUBLIC;
GRANT INSERT (type, recipient_domain, outcome, provider, provider_message_id, detail, at)
    ON consentvault.notify_send_log TO consentvault_app, consentvault_worker;
GRANT SELECT ON consentvault.notify_send_log TO consentvault_operator;
