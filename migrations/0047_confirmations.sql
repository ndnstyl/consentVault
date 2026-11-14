-- Confirmation messages (confirmations.md sections 1 to 9): the sending accounts an organization connects, the rules and
-- templates, the sender's queue and what it sent, the replies it received and the bookkeeping that keeps inbound requests
-- honest (seen message ids, failure counts, page tokens). Every table is row-secured by org_id like every tenant table.
--
-- * sending_account holds the customer's own provider credentials. The secret columns (credentials_ct, credential_ids_ct,
--   auth_token_ct) are never granted to the runtime role for reading; the one owner-rights function that returns them
--   (0048) checks the token's scope. A Twilio auth token is kept only to check request signatures.
-- * confirmation_send_intent is the queue and the life of a send: one row per (contact, channel, grant), inserted in the
--   grant's own transaction. confirmation_send is the append-only record of a message the provider accepted (the exact text
--   sealed under the contact's key, its SHA-256, the provider message id); confirmation_send_status is append-only too.
-- * confirmation_reply keeps an inbound text as received, sealed. Under the contact's key when the number matches a record;
--   under the organization's display key when it matches none, and then deleted 30 days after it arrived.
-- * Nothing here holds a contact point in clear.
CREATE TABLE consentvault.sending_account (
    org_id               uuid NOT NULL REFERENCES consentvault.organization (org_id),
    account_id           uuid NOT NULL DEFAULT gen_random_uuid(),
    channel              text NOT NULL CHECK (channel IN ('email', 'sms')),
    provider             text NOT NULL CHECK (provider IN ('twilio', 'ses', 'postmark')),
    status               text NOT NULL DEFAULT 'awaiting_test_reply'
                         CHECK (status IN ('connected', 'awaiting_test_reply', 'failing', 'disconnected')),
    from_email           text CHECK (from_email IS NULL OR length(from_email) <= 320),
    from_display_name    text CHECK (from_display_name IS NULL OR length(from_display_name) <= 200),
    account_sid          text CHECK (account_sid IS NULL OR account_sid ~ '^AC[0-9a-f]{32}$'),
    sender_id            text CHECK (sender_id IS NULL OR length(sender_id) <= 100),
    number_hint          text CHECK (number_hint IS NULL OR length(number_hint) <= 20),
    sender_ct            bytea,
    inbound_key          text CHECK (inbound_key IS NULL OR length(inbound_key) BETWEEN 20 AND 100),
    inbound_url          text CHECK (inbound_url IS NULL OR length(inbound_url) <= 500),
    provider_replies     jsonb,
    replies_answered_by  uuid,
    replies_answered_at  timestamptz,
    inbound_verified_at  timestamptz,
    last_check           jsonb,
    credentials_ct       bytea,
    credential_ids_ct    bytea,
    auth_token_ct        bytea,
    refusal_count        integer NOT NULL DEFAULT 0 CHECK (refusal_count >= 0),
    last_refusal_code    text CHECK (last_refusal_code IS NULL OR length(last_refusal_code) <= 60),
    created_by           uuid,
    created_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    disconnected_at      timestamptz,
    PRIMARY KEY (org_id, account_id),
    CONSTRAINT sending_account_provider_channel CHECK ((provider = 'twilio') = (channel = 'sms')),
    CONSTRAINT sending_account_sms_shape CHECK (channel <> 'sms' OR (inbound_key IS NOT NULL AND inbound_url IS NOT NULL
                                                                     AND provider_replies IS NOT NULL))
);
CREATE UNIQUE INDEX sending_account_inbound_key_idx ON consentvault.sending_account (inbound_key) WHERE inbound_key IS NOT NULL;
CREATE UNIQUE INDEX sending_account_one_live_idx ON consentvault.sending_account (org_id, channel) WHERE status <> 'disconnected';

CREATE TABLE consentvault.confirmation_settings (
    org_id            uuid NOT NULL REFERENCES consentvault.organization (org_id),
    version           integer NOT NULL CHECK (version >= 1),
    organization_name text NOT NULL CHECK (length(organization_name) BETWEEN 1 AND 200),
    postal_address    text NOT NULL CHECK (length(postal_address) BETWEEN 1 AND 300),
    help_email        text NOT NULL CHECK (length(help_email) BETWEEN 3 AND 320),
    help_phone        text CHECK (help_phone IS NULL OR help_phone ~ '^\+[0-9]{7,15}$'),
    send_cap_per_hour integer NOT NULL DEFAULT 500 CHECK (send_cap_per_hour BETWEEN 1 AND 10000),
    created_by        uuid,
    created_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, version)
);

CREATE TABLE consentvault.confirmation_link_host (
    org_id          uuid PRIMARY KEY REFERENCES consentvault.organization (org_id),
    host            text NOT NULL CHECK (length(host) BETWEEN 4 AND 253 AND host = lower(host)),
    status          text NOT NULL DEFAULT 'pending_dns' CHECK (status IN ('pending_dns', 'verified', 'failing')),
    txt_value       text NOT NULL CHECK (length(txt_value) BETWEEN 16 AND 200),
    fail_count      integer NOT NULL DEFAULT 0 CHECK (fail_count >= 0),
    last_checked_at timestamptz,
    verified_at     timestamptz,
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX confirmation_link_host_live_idx ON consentvault.confirmation_link_host (host) WHERE status IN ('verified', 'failing');

CREATE TABLE consentvault.confirmation_registration (
    org_id                    uuid PRIMARY KEY REFERENCES consentvault.organization (org_id),
    status                    text NOT NULL CHECK (status IN ('not_marked', 'marked')),
    kind                      text CHECK (kind IS NULL OR kind IN ('10dlc', 'toll_free', 'short_code')),
    reference                 text CHECK (reference IS NULL OR length(reference) BETWEEN 1 AND 100),
    samples_statement_version integer CHECK (samples_statement_version IS NULL OR samples_statement_version >= 1),
    marked_by                 uuid,
    marked_at                 timestamptz,
    withdrawn_at              timestamptz,
    CONSTRAINT confirmation_registration_marked_shape CHECK (status <> 'marked' OR
        (kind IS NOT NULL AND samples_statement_version IS NOT NULL AND marked_by IS NOT NULL AND marked_at IS NOT NULL))
);

CREATE TABLE consentvault.confirmation_template (
    org_id       uuid NOT NULL REFERENCES consentvault.organization (org_id),
    template_id  uuid NOT NULL DEFAULT gen_random_uuid(),
    version      integer NOT NULL CHECK (version >= 1),
    subject      text NOT NULL CHECK (length(subject) BETWEEN 1 AND 80),
    opening_line text CHECK (opening_line IS NULL OR length(opening_line) <= 300),
    created_by   uuid,
    created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, template_id)
);

CREATE TABLE consentvault.confirmation_rule (
    org_id                uuid NOT NULL REFERENCES consentvault.organization (org_id),
    source_id             uuid NOT NULL,
    channel               text NOT NULL CHECK (channel IN ('email', 'sms')),
    enabled               boolean NOT NULL DEFAULT false,
    sending_brand_id      uuid,
    template_id           uuid,
    send_for_test_events  boolean NOT NULL DEFAULT true,
    dedupe_hours          integer NOT NULL DEFAULT 24 CHECK (dedupe_hours BETWEEN 1 AND 168),
    max_delay_minutes     integer NOT NULL DEFAULT 10 CHECK (max_delay_minutes BETWEEN 1 AND 60),
    updated_by            uuid,
    updated_at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, source_id, channel),
    FOREIGN KEY (org_id, source_id) REFERENCES consentvault.capture_source (org_id, source_id),
    FOREIGN KEY (org_id, sending_brand_id) REFERENCES consentvault.brand (org_id, brand_id),
    FOREIGN KEY (org_id, template_id) REFERENCES consentvault.confirmation_template (org_id, template_id),
    CONSTRAINT confirmation_rule_template_email_only CHECK (template_id IS NULL OR channel = 'email')
);

CREATE TABLE consentvault.confirmation_send_intent (
    org_id                 uuid NOT NULL REFERENCES consentvault.organization (org_id),
    send_id                uuid NOT NULL DEFAULT gen_random_uuid(),
    kind                   text NOT NULL DEFAULT 'confirmation'
                           CHECK (kind IN ('confirmation', 'optout_reply', 'help_reply', 'start_reply')),
    basis_event_id         uuid,
    source_id              uuid,
    reply_id               uuid,
    contact_fp             text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    channel                text NOT NULL CHECK (channel IN ('email', 'sms')),
    status                 text NOT NULL DEFAULT 'intent'
                           CHECK (status IN ('intent', 'sending', 'sent', 'delivered', 'failed', 'dead', 'skipped')),
    attempts               integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    first_attempt_at       timestamptz,
    last_attempt_at        timestamptz,
    next_attempt_at        timestamptz,
    skip_reason            text CHECK (skip_reason IS NULL OR skip_reason ~ '^[a-z_]{3,40}$'),
    dead_cause             text CHECK (dead_cause IS NULL OR length(dead_cause) <= 60),
    failed_code            text CHECK (failed_code IS NULL OR length(failed_code) <= 60),
    last_error             text CHECK (last_error IS NULL OR length(last_error) <= 60),
    provider_status        text CHECK (provider_status IS NULL OR length(provider_status) <= 40),
    provider_message_id    text CHECK (provider_message_id IS NULL OR length(provider_message_id) <= 200),
    provider_refusal_stop  boolean NOT NULL DEFAULT false,
    dest_ct                bytea,
    body_ct                bytea,
    created_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    at                     timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, send_id),
    FOREIGN KEY (org_id, basis_event_id) REFERENCES consentvault.event (org_id, event_id),
    CONSTRAINT confirmation_send_intent_skip_shape CHECK ((status = 'skipped') = (skip_reason IS NOT NULL)),
    CONSTRAINT confirmation_send_intent_dead_shape CHECK (status = 'dead' OR dead_cause IS NULL),
    CONSTRAINT confirmation_send_intent_kind_shape CHECK ((kind = 'confirmation') = (reply_id IS NULL))
);
CREATE UNIQUE INDEX confirmation_send_intent_basis_idx
    ON consentvault.confirmation_send_intent (org_id, contact_fp, channel, basis_event_id) WHERE basis_event_id IS NOT NULL;
CREATE UNIQUE INDEX confirmation_send_intent_reply_idx
    ON consentvault.confirmation_send_intent (org_id, reply_id, kind) WHERE reply_id IS NOT NULL;
CREATE INDEX confirmation_send_intent_due_idx ON consentvault.confirmation_send_intent (org_id, created_at, send_id)
    WHERE status = 'intent';
CREATE INDEX confirmation_send_intent_list_idx ON consentvault.confirmation_send_intent (org_id, at DESC, send_id DESC);
CREATE INDEX confirmation_send_intent_contact_idx ON consentvault.confirmation_send_intent (org_id, contact_fp, channel, at);
CREATE UNIQUE INDEX confirmation_send_intent_provider_idx
    ON consentvault.confirmation_send_intent (org_id, provider_message_id) WHERE provider_message_id IS NOT NULL;

CREATE TABLE consentvault.confirmation_send (
    org_id              uuid NOT NULL REFERENCES consentvault.organization (org_id),
    send_id             uuid NOT NULL,
    provider_message_id text NOT NULL CHECK (length(provider_message_id) BETWEEN 1 AND 200),
    body_ct             bytea NOT NULL,
    body_sha256         text NOT NULL CHECK (body_sha256 ~ '^[0-9a-f]{64}$'),
    fixed_text_version  integer NOT NULL CHECK (fixed_text_version >= 1),
    template_id         uuid,
    sent_at             timestamptz NOT NULL,
    PRIMARY KEY (org_id, send_id),
    FOREIGN KEY (org_id, send_id) REFERENCES consentvault.confirmation_send_intent (org_id, send_id)
);

CREATE TABLE consentvault.confirmation_send_status (
    org_id          uuid NOT NULL REFERENCES consentvault.organization (org_id),
    status_id       uuid NOT NULL DEFAULT gen_random_uuid(),
    send_id         uuid NOT NULL,
    provider_status text NOT NULL CHECK (length(provider_status) BETWEEN 1 AND 40),
    error_code      text CHECK (error_code IS NULL OR length(error_code) <= 60),
    received_at     timestamptz NOT NULL,
    PRIMARY KEY (org_id, status_id),
    FOREIGN KEY (org_id, send_id) REFERENCES consentvault.confirmation_send_intent (org_id, send_id)
);
CREATE INDEX confirmation_send_status_send_idx ON consentvault.confirmation_send_status (org_id, send_id, received_at);

CREATE TABLE consentvault.confirmation_reply (
    org_id              uuid NOT NULL REFERENCES consentvault.organization (org_id),
    reply_id            uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id          uuid NOT NULL,
    from_fp             text NOT NULL CHECK (from_fp ~ '^[0-9a-f]{64}$'),
    matched_record_id   uuid,
    body_ct             bytea NOT NULL,
    from_ct             bytea,
    key_kind            text NOT NULL CHECK (key_kind IN ('contact', 'org')),
    received_at         timestamptz NOT NULL,
    provider_message_id text NOT NULL CHECK (length(provider_message_id) BETWEEN 1 AND 200),
    verdict             text NOT NULL CHECK (verdict IN ('stop', 'start', 'help', 'needs_review', 'not_stop')),
    reason              text NOT NULL CHECK (length(reason) <= 300),
    matched_words       text[] NOT NULL DEFAULT '{}',
    state               text NOT NULL DEFAULT 'to_read' CHECK (state IN ('to_read', 'stop', 'not_stop', 'help', 'start')),
    event_id            uuid,
    marked_by           uuid,
    marked_at           timestamptz,
    mark_reason         text CHECK (mark_reason IS NULL OR length(mark_reason) BETWEEN 1 AND 200),
    PRIMARY KEY (org_id, reply_id),
    FOREIGN KEY (org_id, account_id) REFERENCES consentvault.sending_account (org_id, account_id),
    FOREIGN KEY (org_id, event_id) REFERENCES consentvault.event (org_id, event_id),
    CONSTRAINT confirmation_reply_unmatched_keeps_number CHECK ((key_kind = 'org') = (from_ct IS NOT NULL))
);
CREATE INDEX confirmation_reply_list_idx ON consentvault.confirmation_reply (org_id, received_at DESC, reply_id DESC);
CREATE INDEX confirmation_reply_unread_idx ON consentvault.confirmation_reply (org_id, received_at) WHERE state = 'to_read';

CREATE TABLE consentvault.confirmation_connect_test (
    org_id              uuid NOT NULL REFERENCES consentvault.organization (org_id),
    account_id          uuid NOT NULL,
    provider_message_id text NOT NULL CHECK (length(provider_message_id) BETWEEN 1 AND 200),
    received_at         timestamptz NOT NULL,
    from_fp             text NOT NULL CHECK (from_fp ~ '^[0-9a-f]{64}$'),
    body_ct             bytea NOT NULL,
    PRIMARY KEY (org_id, account_id, provider_message_id),
    FOREIGN KEY (org_id, account_id) REFERENCES consentvault.sending_account (org_id, account_id)
);

CREATE TABLE consentvault.confirmation_inbound_seen (
    org_id              uuid NOT NULL REFERENCES consentvault.organization (org_id),
    provider            text NOT NULL CHECK (provider IN ('twilio')),
    provider_message_id text NOT NULL CHECK (length(provider_message_id) BETWEEN 1 AND 200),
    seen_at             timestamptz NOT NULL,
    PRIMARY KEY (org_id, provider, provider_message_id)
);

CREATE TABLE consentvault.confirmation_inbound_failure (
    org_id     uuid NOT NULL REFERENCES consentvault.organization (org_id),
    failure_id uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL,
    cause      text NOT NULL CHECK (cause IN ('signature', 'number_mismatch', 'too_large')),
    at         timestamptz NOT NULL,
    PRIMARY KEY (org_id, failure_id)
);
CREATE INDEX confirmation_inbound_failure_at_idx ON consentvault.confirmation_inbound_failure (org_id, at);

CREATE TABLE consentvault.confirmation_page_token (
    org_id     uuid NOT NULL REFERENCES consentvault.organization (org_id),
    token_hash text NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    kind       text NOT NULL CHECK (kind IN ('wording', 'stop')),
    send_id    uuid,
    is_test    boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, token_hash),
    FOREIGN KEY (org_id, send_id) REFERENCES consentvault.confirmation_send_intent (org_id, send_id),
    CONSTRAINT confirmation_page_token_shape CHECK ((send_id IS NULL) = is_test)
);

-- Append-only: what the provider accepted, what it reported, which message ids were seen -----------------------------------------
CREATE TRIGGER confirmation_send_append_only BEFORE UPDATE OR DELETE ON consentvault.confirmation_send
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER confirmation_send_status_append_only BEFORE UPDATE OR DELETE ON consentvault.confirmation_send_status
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER confirmation_inbound_seen_append_only BEFORE UPDATE OR DELETE ON consentvault.confirmation_inbound_seen
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();

-- Row security: by organization on every table; the tables that hold text a person wrote or a message we sent open only to a
-- read scope (the pattern of may_read_evidence): a developer token reads the queue and the accounts, never the text. -----------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['sending_account', 'confirmation_settings', 'confirmation_link_host', 'confirmation_registration',
                             'confirmation_template', 'confirmation_rule', 'confirmation_send_intent', 'confirmation_send',
                             'confirmation_send_status', 'confirmation_reply', 'confirmation_connect_test',
                             'confirmation_inbound_seen', 'confirmation_inbound_failure', 'confirmation_page_token'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
        EXECUTE format('REVOKE ALL ON consentvault.%I FROM PUBLIC', t);
    END LOOP;
    FOREACH t IN ARRAY ARRAY['confirmation_send', 'confirmation_reply', 'confirmation_connect_test'] LOOP
        EXECUTE format('CREATE POLICY %I ON consentvault.%I AS RESTRICTIVE FOR SELECT USING ((SELECT consentvault.may_read_evidence()))',
                       t || '_read_scope', t);
    END LOOP;
END
$$;

-- Grants to the runtime role. The secret columns of sending_account are written but never read back by a session. -------------
GRANT SELECT (org_id, account_id, channel, provider, status, from_email, from_display_name, account_sid, sender_id, number_hint, sender_ct,
              inbound_key, inbound_url, provider_replies, replies_answered_by, replies_answered_at, inbound_verified_at,
              last_check, refusal_count, last_refusal_code, created_by, created_at, disconnected_at)
    ON consentvault.sending_account TO consentvault_app;
GRANT INSERT ON consentvault.sending_account TO consentvault_app;
GRANT UPDATE (status, provider_replies, replies_answered_by, replies_answered_at, inbound_verified_at, last_check,
              credentials_ct, credential_ids_ct, auth_token_ct, refusal_count, last_refusal_code, disconnected_at)
    ON consentvault.sending_account TO consentvault_app;
GRANT SELECT, INSERT ON consentvault.confirmation_settings, consentvault.confirmation_template TO consentvault_app;
GRANT SELECT, INSERT, UPDATE ON consentvault.confirmation_link_host, consentvault.confirmation_registration,
    consentvault.confirmation_rule, consentvault.confirmation_send_intent TO consentvault_app;
GRANT SELECT, INSERT ON consentvault.confirmation_send, consentvault.confirmation_send_status,
    consentvault.confirmation_inbound_seen TO consentvault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON consentvault.confirmation_reply TO consentvault_app;
GRANT SELECT, INSERT, DELETE ON consentvault.confirmation_connect_test, consentvault.confirmation_inbound_failure,
    consentvault.confirmation_page_token TO consentvault_app;

-- The operator-owned lookups of 0048 read across organizations; they read only these columns. -----------------------------------
GRANT SELECT (org_id, account_id, inbound_key) ON consentvault.sending_account TO consentvault_operator;
GRANT SELECT (org_id, host, status) ON consentvault.confirmation_link_host TO consentvault_operator;
GRANT SELECT (org_id, status) ON consentvault.confirmation_send_intent TO consentvault_operator;
