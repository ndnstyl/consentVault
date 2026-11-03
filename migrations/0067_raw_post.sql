-- The raw post store: every request that reaches an intake is written here first, whole, before anything reads it.
--
-- raw_post is what was received (append-only, one hash chain per organisation, its own head table for anchors). The
-- tables beside it hold what the transport knew (raw_post_fact), where a form puts its fields (form_field_map), the
-- exact values copied out of a stored post (raw_post_field), the link between a post and a contact point
-- (raw_post_match) and the outside timestamps (raw_post_seal). Nothing here touches event, seal, chain_head,
-- contact_salt or any other existing table: the event chain and every existing seal stay exactly as they were, and no
-- column of a sealed table changes shape.
--
-- Database checks on raw_post are limited to: id and hash shapes, the chain extending its organisation's head under the
-- organisation's lock, the arrival clock being the database's own, and exactly one of the inline body or the object
-- holding it. There is no check on any posted value.
--
-- Every table follows the conventions of 0002: org_id NOT NULL with a foreign key, ENABLE and FORCE ROW LEVEL SECURITY,
-- one policy on (SELECT consentvault.current_org()), evidence tables also behind the evidence read scope, append-only.
-- A post that names no organisation is stored on the home organisation's chain (the platform's own), labelled by its
-- intake; it is never dropped for want of an organisation.

CREATE FUNCTION consentvault.raw_post_lock_key(p_org uuid) RETURNS integer
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.hashtext('consentvault.raw_post:' OPERATOR(pg_catalog.||) p_org::pg_catalog.text);
$$;
REVOKE ALL ON FUNCTION consentvault.raw_post_lock_key(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.raw_post_lock_key(uuid) TO consentvault_app, consentvault_worker;

-- 1. raw_post: what was received ---------------------------------------------------------------------------------------
CREATE TABLE consentvault.raw_post (
    org_id               uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    post_id              uuid NOT NULL,
    seq                  bigint NOT NULL CHECK (seq >= 1),
    intake               text NOT NULL,
    received_at          timestamptz NOT NULL,
    method               text NOT NULL,
    path                 text NOT NULL,
    query_ct             bytea NOT NULL,
    headers_ct           bytea NOT NULL,
    body_ct              bytea,
    body_object_id       uuid,
    body_bytes           bigint NOT NULL CHECK (body_bytes >= 0),
    body_sha256          text NOT NULL CHECK (body_sha256 ~ '^[0-9a-f]{64}$'),
    unusual_size         boolean NOT NULL,
    edge_received_at     timestamptz,
    headers_presented_by text NOT NULL,
    kind                 text NOT NULL,
    encryption           text NOT NULL,
    prev_hash            text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    row_hash             text NOT NULL CHECK (row_hash ~ '^[0-9a-f]{64}$'),
    hash_version         integer NOT NULL CHECK (hash_version = 3),
    PRIMARY KEY (org_id, seq),
    CONSTRAINT raw_post_org_post_key UNIQUE (org_id, post_id),
    CONSTRAINT raw_post_org_row_hash_key UNIQUE (org_id, row_hash),
    CONSTRAINT raw_post_one_body CHECK ((body_ct IS NULL) <> (body_object_id IS NULL))
);
CREATE INDEX raw_post_received_idx ON consentvault.raw_post (org_id, received_at);

CREATE TRIGGER raw_post_append_only BEFORE UPDATE OR DELETE ON consentvault.raw_post
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER raw_post_no_truncate BEFORE TRUNCATE ON consentvault.raw_post
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER raw_post_received_check BEFORE INSERT ON consentvault.raw_post
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_received_at();

-- Fork guard: an insert must extend its organisation's raw-post head, under that organisation's raw-post lock.
CREATE FUNCTION consentvault.check_raw_post_chain() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    head_seq  pg_catalog.int8;
    head_hash pg_catalog.text;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(consentvault.raw_post_lock_key(NEW.org_id));
    SELECT seq, row_hash INTO head_seq, head_hash FROM consentvault.raw_post
     WHERE org_id OPERATOR(pg_catalog.=) NEW.org_id ORDER BY seq DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.seq OPERATOR(pg_catalog.<>) 1
           OR NEW.prev_hash OPERATOR(pg_catalog.<>) pg_catalog.repeat('0', 64) THEN
            RAISE EXCEPTION 'consentvault raw post chain: the first post must have seq 1 and the genesis prev_hash'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF NEW.seq OPERATOR(pg_catalog.<>) (head_seq OPERATOR(pg_catalog.+) 1)
          OR NEW.prev_hash OPERATOR(pg_catalog.<>) head_hash THEN
        RAISE EXCEPTION 'consentvault raw post chain: the post does not extend the current head (expected seq %)',
            head_seq OPERATOR(pg_catalog.+) 1
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER raw_post_chain_head BEFORE INSERT ON consentvault.raw_post
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_raw_post_chain();

-- The writer's one read of the chain, for any scope of the current tenant (no personal data).
CREATE FUNCTION consentvault.raw_post_head() RETURNS TABLE (seq bigint, row_hash text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT p.seq, p.row_hash FROM consentvault.raw_post p
     WHERE p.org_id OPERATOR(pg_catalog.=) consentvault.current_org() ORDER BY p.seq DESC LIMIT 1;
$$;
REVOKE ALL ON FUNCTION consentvault.raw_post_head() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.raw_post_head() TO consentvault_app, consentvault_integrity, consentvault_console;

-- 1a. raw_post_key: the per-post data key, wrapped, kept apart ----------------------------------------------------------
-- Not covered by any row hash or seal. The one table where a row may be deleted, by erase_raw_post_key and nothing
-- else (the contact_key pattern): deleting the row makes the post's bytes unreadable; the raw_post row, its hash and the
-- chain are untouched.
CREATE TABLE consentvault.raw_post_key (
    org_id           uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    post_id          uuid NOT NULL,
    post_key_wrapped bytea NOT NULL,
    key_version      integer NOT NULL CHECK (key_version >= 1),
    created_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, post_id),
    FOREIGN KEY (org_id, post_id) REFERENCES consentvault.raw_post (org_id, post_id),
    FOREIGN KEY (org_id, key_version) REFERENCES consentvault.org_key (org_id, version)
);
CREATE TRIGGER raw_post_key_no_update BEFORE UPDATE ON consentvault.raw_post_key
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER raw_post_key_no_truncate BEFORE TRUNCATE ON consentvault.raw_post_key
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

CREATE FUNCTION consentvault.raw_post_key_delete_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF pg_catalog.current_setting('consentvault.erasing_raw_post_key', true) IS DISTINCT FROM OLD.post_id::pg_catalog.text THEN
        RAISE EXCEPTION 'consentvault.raw_post_key: a key row is deleted only by consentvault.erase_raw_post_key'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN OLD;
END;
$$;
CREATE TRIGGER raw_post_key_delete_guard BEFORE DELETE ON consentvault.raw_post_key
    FOR EACH ROW EXECUTE FUNCTION consentvault.raw_post_key_delete_guard();

CREATE FUNCTION consentvault.erase_raw_post_key(p_post_id uuid) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org pg_catalog.uuid := consentvault.current_org();
    n   pg_catalog.int8;
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault erase_raw_post_key: no tenant entered' USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    PERFORM pg_catalog.set_config('consentvault.erasing_raw_post_key', p_post_id::pg_catalog.text, true);
    DELETE FROM consentvault.raw_post_key WHERE org_id OPERATOR(pg_catalog.=) org AND post_id OPERATOR(pg_catalog.=) p_post_id;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM pg_catalog.set_config('consentvault.erasing_raw_post_key', '', true);
    RETURN n OPERATOR(pg_catalog.>) 0;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.erase_raw_post_key(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.erase_raw_post_key(uuid) TO consentvault_console;

-- 1b. raw_post_chain_head: anchors of the raw-post chain (the chain_head pattern) ---------------------------------------
CREATE TABLE consentvault.raw_post_chain_head (
    head_uuid   uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id      uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    seq         bigint NOT NULL CHECK (seq >= 1),
    row_hash    text NOT NULL CHECK (row_hash ~ '^[0-9a-f]{64}$'),
    sink        text,
    anchored_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER raw_post_chain_head_append_only BEFORE UPDATE OR DELETE ON consentvault.raw_post_chain_head
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER raw_post_chain_head_no_truncate BEFORE TRUNCATE ON consentvault.raw_post_chain_head
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- 2. raw_post_fact: what the transport knew ----------------------------------------------------------------------------
CREATE TABLE consentvault.raw_post_fact (
    org_id      uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    post_id     uuid NOT NULL,
    fact_id     uuid NOT NULL,
    source      text NOT NULL,
    name        text NOT NULL,
    value_ct    bytea NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, post_id, fact_id),
    FOREIGN KEY (org_id, post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE TRIGGER raw_post_fact_append_only BEFORE UPDATE OR DELETE ON consentvault.raw_post_fact
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER raw_post_fact_no_truncate BEFORE TRUNCATE ON consentvault.raw_post_fact
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- 3. form_field_map: where a form puts its fields ----------------------------------------------------------------------
-- Versioned per capture source (source_id NULL: the organisation's default for posts with no map of their own).
-- A new version is a new row; an old version is never edited.
CREATE TABLE consentvault.form_field_map (
    org_id                uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    map_id                uuid NOT NULL DEFAULT gen_random_uuid(),
    source_id             uuid,
    map_version           integer NOT NULL CHECK (map_version >= 1),
    consent_ticked_value  text,
    body_format           text NOT NULL CHECK (body_format IN ('json', 'form_urlencoded', 'multipart', 'text')),
    consent_paths         text[] NOT NULL,
    decision_time_path    text,
    wording_path          text,
    wording_hash_path     text,
    seller_paths          text[],
    form_version_path     text,
    checkbox_default_path text,
    submit_context_path   text,
    third_party_cert_path text,
    jurisdiction_path     text,
    channel_scope_path    text,
    contact_paths         jsonb NOT NULL DEFAULT '[]'::jsonb,
    set_by                text NOT NULL,
    set_at                timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, map_id),
    FOREIGN KEY (org_id, source_id) REFERENCES consentvault.capture_source (org_id, source_id)
);
CREATE UNIQUE INDEX form_field_map_version_key ON consentvault.form_field_map
    (org_id, coalesce(source_id, '00000000-0000-0000-0000-000000000000'::uuid), map_version);
CREATE TRIGGER form_field_map_append_only BEFORE UPDATE OR DELETE ON consentvault.form_field_map
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER form_field_map_no_truncate BEFORE TRUNCATE ON consentvault.form_field_map
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- 4. raw_post_field: the exact values, copied --------------------------------------------------------------------------
CREATE TABLE consentvault.raw_post_field (
    org_id               uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    post_id              uuid NOT NULL,
    map_version          integer NOT NULL CHECK (map_version >= 0),
    field                text NOT NULL,
    state                text NOT NULL CHECK (state IN ('sent', 'not_sent', 'sent_more_than_once', 'unmapped', 'body_unreadable')),
    values_ct            bytea,
    occurrences          integer NOT NULL CHECK (occurrences >= 0),
    decision_time_parsed timestamptz,
    extracted_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, post_id, map_version, field),
    FOREIGN KEY (org_id, post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE TRIGGER raw_post_field_append_only BEFORE UPDATE OR DELETE ON consentvault.raw_post_field
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER raw_post_field_no_truncate BEFORE TRUNCATE ON consentvault.raw_post_field
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- 5. raw_post_match: the link and the change ---------------------------------------------------------------------------
CREATE TABLE consentvault.raw_post_match (
    org_id                        uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    post_id                       uuid NOT NULL,
    match_id                      uuid NOT NULL,
    map_version                   integer NOT NULL CHECK (map_version >= 0),
    status                        text NOT NULL CHECK (status IN ('matched', 'unmatched')),
    unmatched_reason              text,
    contact_kind                  text,
    contact_fp                    text CHECK (contact_fp IS NULL OR contact_fp ~ '^[0-9a-f]{64}$'),
    record_id                     uuid,
    previous_post_id              uuid,
    previous_same_source_post_id  uuid,
    consent_before_ct             bytea,
    consent_after_ct              bytea,
    changed                       boolean,
    wording_changed               boolean,
    same_fingerprint_as_previous  boolean,
    matched_at                    timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, post_id, match_id),
    FOREIGN KEY (org_id, post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE INDEX raw_post_match_fp_idx ON consentvault.raw_post_match (org_id, contact_fp) WHERE contact_fp IS NOT NULL;
CREATE TRIGGER raw_post_match_append_only BEFORE UPDATE OR DELETE ON consentvault.raw_post_match
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER raw_post_match_no_truncate BEFORE TRUNCATE ON consentvault.raw_post_match
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- 6. raw_post_seal: outside timestamps ---------------------------------------------------------------------------------
-- The seal names the exact column list its digest covers (the consent-evidence rule): verification digests only those.
CREATE TABLE consentvault.raw_post_seal (
    seal_uuid    uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id       uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    post_id      uuid NOT NULL,
    hash_version integer NOT NULL,
    columns      text[] NOT NULL,
    digest       bytea NOT NULL CHECK (octet_length(digest) = 32),
    tsa_url      text NOT NULL,
    token        bytea NOT NULL,
    gen_time     timestamptz,
    verified_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (org_id, post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE INDEX raw_post_seal_post_idx ON consentvault.raw_post_seal (org_id, post_id);

CREATE FUNCTION consentvault.raw_post_seal_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.raw_post_seal is append-only: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (pg_catalog.to_jsonb(NEW) OPERATOR(pg_catalog.-) 'verified_at'::pg_catalog.text)
           IS DISTINCT FROM (pg_catalog.to_jsonb(OLD) OPERATOR(pg_catalog.-) 'verified_at'::pg_catalog.text) THEN
        RAISE EXCEPTION 'consentvault.raw_post_seal is append-only: only verified_at may change'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER raw_post_seal_guard BEFORE UPDATE OR DELETE ON consentvault.raw_post_seal
    FOR EACH ROW EXECUTE FUNCTION consentvault.raw_post_seal_guard();
CREATE TRIGGER raw_post_seal_no_truncate BEFORE TRUNCATE ON consentvault.raw_post_seal
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

CREATE FUNCTION consentvault.mark_raw_post_seal_verified(p_seal_uuid uuid) RETURNS void
    LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    UPDATE consentvault.raw_post_seal SET verified_at = pg_catalog.clock_timestamp()
     WHERE seal_uuid OPERATOR(pg_catalog.=) p_seal_uuid AND org_id OPERATOR(pg_catalog.=) consentvault.current_org()
       AND verified_at IS NULL;
$$;
REVOKE ALL ON FUNCTION consentvault.mark_raw_post_seal_verified(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.mark_raw_post_seal_verified(uuid) TO consentvault_app, consentvault_integrity;

-- 6a. event_source_post: which post a derived event came from ------------------------------------------------------------
-- Append-only (org, event, post, role): ``trigger`` is the request that caused the event, ``reference`` an earlier record the
-- derived feature relied on. A separate table, so no column is added to the sealed event table.
CREATE TABLE consentvault.event_source_post (
    org_id      uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    event_id    uuid NOT NULL,
    post_id     uuid NOT NULL,
    role        text NOT NULL CHECK (role IN ('trigger', 'reference')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, event_id, post_id, role),
    FOREIGN KEY (org_id, event_id) REFERENCES consentvault.event (org_id, event_id),
    FOREIGN KEY (org_id, post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE TRIGGER event_source_post_append_only BEFORE UPDATE OR DELETE ON consentvault.event_source_post
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER event_source_post_no_truncate BEFORE TRUNCATE ON consentvault.event_source_post
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Row-level security -----------------------------------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['raw_post', 'raw_post_key', 'raw_post_chain_head', 'raw_post_fact', 'form_field_map',
                             'raw_post_field', 'raw_post_match', 'raw_post_seal', 'event_source_post'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
    END LOOP;
    -- A capture token writes but cannot read back; a form field map is configuration and is not behind the read scope.
    FOREACH t IN ARRAY ARRAY['raw_post', 'raw_post_key', 'raw_post_chain_head', 'raw_post_fact', 'raw_post_field',
                             'raw_post_match', 'raw_post_seal', 'event_source_post'] LOOP
        EXECUTE format('CREATE POLICY %I ON consentvault.%I AS RESTRICTIVE FOR SELECT'
                       ' USING ((SELECT consentvault.may_read_evidence()))', t || '_read_scope', t);
    END LOOP;
END
$$;

-- Grants -----------------------------------------------------------------------------------------------------------------
-- The runtime role appends and reads (reads still pass the evidence read scope); nothing here is ever updated.
GRANT SELECT, INSERT ON consentvault.raw_post, consentvault.raw_post_key, consentvault.raw_post_fact,
    consentvault.raw_post_field, consentvault.raw_post_match, consentvault.raw_post_chain_head,
    consentvault.event_source_post TO consentvault_app;
GRANT SELECT ON consentvault.form_field_map TO consentvault_app;
GRANT SELECT, INSERT ON consentvault.raw_post_seal TO consentvault_app;  -- the single-company seal job runs as the runtime role
GRANT SELECT, INSERT ON consentvault.form_field_map TO consentvault_console;
GRANT SELECT ON consentvault.raw_post, consentvault.raw_post_fact, consentvault.raw_post_field, consentvault.raw_post_match,
    consentvault.raw_post_key, consentvault.event_source_post TO consentvault_console;
GRANT SELECT ON consentvault.raw_post, consentvault.raw_post_seal, consentvault.raw_post_chain_head TO consentvault_integrity;
GRANT INSERT ON consentvault.raw_post_seal, consentvault.raw_post_chain_head TO consentvault_integrity;
