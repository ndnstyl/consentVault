-- Record links (marketing/specs/competitive-builds, Build 1): a customer chooses one sealed record and gets a link a stranger can open
-- with no sign-in. The page shows the record, the integrity checks recomputed from it and a one-record file, and only the fields the
-- sender switched on.
--
-- Nothing here writes a consent event, touches a sealed table or changes a sealed column: a link, a withdrawal, a view, a match
-- attempt and a match reset are each a fact in their own append-only table (the ledger's own layout: the runtime role selects and
-- inserts, a trigger refuses UPDATE and DELETE and TRUNCATE).
--
-- Reading is through one owner-rights function, public_proof_view, executable by one login group (consentvault_public_verify) that
-- reads no table. The function finds the link by the SHA-256 of its id (the id itself is never stored), enters that link's own
-- organisation the way the billing functions do (a short token it signs for itself), applies the link's flags, and returns only the
-- columns those flags allow. Anything encrypted comes back as ciphertext and is opened by the application with the organisation's
-- key; the contact point, the page URL and the raw post body come back only when the link switched them on.
--
-- Erasure: erase_contact (0054's body, plus one statement) withdraws every link for the contact in the same transaction that destroys
-- the contact key.
--
-- The roles are made once per cluster by a superuser (docker/initdb/10-roles.sh, or the managed database's master user); this
-- migration refuses to run without consentvault_public_verify, and its login is made by the deployment as a member of it.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_public_verify') THEN
        RAISE EXCEPTION 'consentvault migration 0112 refused: the role consentvault_public_verify does not exist. As a superuser (or the '
                        'managed database master user) run: CREATE ROLE consentvault_public_verify NOLOGIN; then create its login as a '
                        'member of it (docs/deployment.md, "Roles")'
            USING ERRCODE = 'undefined_object';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'consentvault_public_verify' AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
        RAISE EXCEPTION 'consentvault migration 0112 refused: consentvault_public_verify must be a NOLOGIN group, neither a superuser nor BYPASSRLS'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
END
$$;

-- 1. The link ----------------------------------------------------------------------------------------------------------------
CREATE TABLE consentvault.proof_share (
    org_id               uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    share_id             uuid NOT NULL DEFAULT gen_random_uuid(),
    link_digest          text NOT NULL CHECK (link_digest ~ '^[0-9a-f]{64}$'),
    event_id             uuid NOT NULL,
    raw_post_id          uuid,
    show_org_name        boolean NOT NULL DEFAULT true,
    show_contact         boolean NOT NULL DEFAULT false,
    allow_contact_match  boolean NOT NULL DEFAULT true,
    show_page_url        boolean NOT NULL DEFAULT false,
    show_bot_check       boolean NOT NULL DEFAULT false,
    created_by           text NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    note                 text NOT NULL DEFAULT '',
    code_version         text NOT NULL,
    PRIMARY KEY (org_id, share_id),
    CONSTRAINT proof_share_link_digest_key UNIQUE (link_digest),
    FOREIGN KEY (org_id, event_id) REFERENCES consentvault.event (org_id, event_id),
    FOREIGN KEY (org_id, raw_post_id) REFERENCES consentvault.raw_post (org_id, post_id)
);
CREATE INDEX proof_share_event_idx ON consentvault.proof_share (org_id, event_id);

-- 2. A withdrawal: one fact per link, never an edit of the link ---------------------------------------------------------------
CREATE TABLE consentvault.proof_share_revocation (
    org_id     uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    share_id   uuid NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_by text NOT NULL,
    reason     text NOT NULL CHECK (reason IN ('sender', 'erasure', 'org_closed')),
    PRIMARY KEY (org_id, share_id),
    FOREIGN KEY (org_id, share_id) REFERENCES consentvault.proof_share (org_id, share_id)
);

-- 3. The sender reopening a locked match box ----------------------------------------------------------------------------------
CREATE TABLE consentvault.proof_share_reset (
    org_id   uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    reset_id uuid NOT NULL DEFAULT gen_random_uuid(),
    share_id uuid NOT NULL,
    reset_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    reset_by text NOT NULL,
    PRIMARY KEY (org_id, reset_id),
    FOREIGN KEY (org_id, share_id) REFERENCES consentvault.proof_share (org_id, share_id)
);
CREATE INDEX proof_share_reset_idx ON consentvault.proof_share_reset (org_id, share_id, reset_at);

-- 4. A view or a match attempt: the time, the link and the kind, and nothing about who ---------------------------------------
-- No contact point, no address, no browser. A match attempt records yes or no and never what was typed.
CREATE TABLE consentvault.proof_share_view (
    org_id    uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    view_id   uuid NOT NULL DEFAULT gen_random_uuid(),
    share_id  uuid NOT NULL,
    viewed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    kind      text NOT NULL CHECK (kind IN ('page', 'file', 'match_yes', 'match_no', 'match_locked')),
    PRIMARY KEY (org_id, view_id),
    FOREIGN KEY (org_id, share_id) REFERENCES consentvault.proof_share (org_id, share_id)
);
CREATE INDEX proof_share_view_idx ON consentvault.proof_share_view (org_id, share_id, viewed_at);

-- 5. Views past the daily cap: still answered, counted here instead of one fact row each -----------------------------------------
CREATE TABLE consentvault.proof_share_daily_count (
    org_id     uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    count_id   uuid NOT NULL DEFAULT gen_random_uuid(),
    share_id   uuid NOT NULL,
    counted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, count_id),
    FOREIGN KEY (org_id, share_id) REFERENCES consentvault.proof_share (org_id, share_id)
);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['proof_share', 'proof_share_revocation', 'proof_share_reset', 'proof_share_view', 'proof_share_daily_count'] LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON consentvault.%I FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change()',
                       t || '_append_only', t);
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON consentvault.%I FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change()',
                       t || '_no_truncate', t);
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I AS RESTRICTIVE FOR SELECT USING ((SELECT consentvault.may_read_evidence()))',
                       t || '_read_scope', t);
    END LOOP;
END
$$;

-- The runtime role appends and reads. The view and counter tables are written only by public_proof_view, so the runtime role
-- cannot write them at all; the columns a database clock stamps are never insertable.
GRANT SELECT ON consentvault.proof_share, consentvault.proof_share_revocation, consentvault.proof_share_reset,
    consentvault.proof_share_view, consentvault.proof_share_daily_count TO consentvault_app;
GRANT INSERT (org_id, share_id, link_digest, event_id, raw_post_id, show_org_name, show_contact, allow_contact_match, show_page_url,
    show_bot_check, created_by, note, code_version) ON consentvault.proof_share TO consentvault_app;
GRANT INSERT (org_id, share_id, revoked_by, reason) ON consentvault.proof_share_revocation TO consentvault_app;
GRANT INSERT (org_id, share_id, reset_by) ON consentvault.proof_share_reset TO consentvault_app;

-- 6. Finding a link's organisation by the digest of its id: the one non-personal read of the link table that crosses organisations
GRANT SELECT (org_id, link_digest) ON consentvault.proof_share TO consentvault_operator;
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
CREATE FUNCTION consentvault.proof_share_org(p_digest text) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT s.org_id FROM consentvault.proof_share s WHERE s.link_digest = p_digest;
$$;
ALTER FUNCTION consentvault.proof_share_org(text) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.proof_share_org(text) FROM PUBLIC;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;

-- 7. What one record link may carry, for the entered organisation, under the link's flags -----------------------------------------
-- Runs with the caller's rights and the entered tenant's row security, so the runtime role's preview and the public function (which
-- enters the link's organisation first) are one query and one answer. Timestamps leave as ISO text with their offset; bytes leave as hex. The event
-- row is cut to exactly the sealed columns (the hash version 2 list plus prev_hash and row_hash), so no encrypted personal field can
-- ride along. Ciphertext of the contact point and the page URL is added when the flags name each; the raw post body only when both are on.
CREATE FUNCTION consentvault.record_link_material(p_event uuid, p_post uuid, p_show_contact boolean, p_show_page_url boolean,
                                                  p_show_org boolean) RETURNS jsonb
    LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org  uuid := consentvault.current_org();
    e    consentvault.event;
    o    record;
    pr   consentvault.raw_post;
    k    record;
    out  jsonb;
    post jsonb;
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'consentvault record_link_material: no tenant entered' USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    SELECT * INTO e FROM consentvault.event WHERE org_id = org AND event_id = p_event;
    IF NOT FOUND OR e.hash_version <> 2 THEN
        RETURN NULL;
    END IF;
    SELECT g.name, g.default_region INTO o FROM consentvault.organization g WHERE g.org_id = org;
    out := jsonb_build_object(
        'org_id', org, 'org_default_region', o.default_region,
        'org_name', CASE WHEN p_show_org THEN o.name ELSE NULL END,
        'event', (SELECT jsonb_object_agg(x.k, x.v) FROM jsonb_each(to_jsonb(e)) AS x(k, v)
                   WHERE x.k = ANY (ARRAY['seq', 'event_id', 'org_id', 'subject_fp', 'contact_kind', 'contact_fp', 'contact_commit',
                       'subject_commit', 'evidence_sha256', 'event_type', 'channels', 'purposes', 'disclosure_sha256', 'method',
                       'origin', 'captured_at', 'received_at', 'edge_received_at', 'bot_check', 'payload_sha256', 'source',
                       'source_id', 'brand_ids', 'key_version', 'recorded_by', 'release_of_event_id', 'release_outcome',
                       'release_cause', 'contact_verification', 'hash_version', 'prev_hash', 'row_hash'])),
        'disclosure', (SELECT jsonb_build_object('body', d.body, 'sha256', d.sha256, 'label', d.label, 'locale', d.locale)
                         FROM consentvault.disclosure d WHERE d.org_id = org AND d.sha256 = e.disclosure_sha256),
        'seals', (SELECT coalesce(jsonb_agg(jsonb_build_object('seal_id', s.seal_uuid, 'hash_version', s.hash_version,
                          'columns', to_jsonb(s.columns), 'digest_hex', encode(s.digest, 'hex'), 'tsa_url', s.tsa_url,
                          'gen_time', s.gen_time, 'token_hex', encode(s.token, 'hex')) ORDER BY s.created_at, s.seal_uuid), '[]'::jsonb)
                    FROM consentvault.seal s WHERE s.org_id = org AND s.event_id = p_event),
        'anchors', (SELECT coalesce(jsonb_agg(jsonb_build_object('head_id', h.head_uuid, 'seq', h.seq, 'row_hash', h.row_hash,
                          'anchored_at', h.anchored_at) ORDER BY h.seq, h.anchored_at), '[]'::jsonb)
                      FROM (SELECT c.head_uuid, c.seq, c.row_hash, c.anchored_at, c.org_id FROM consentvault.chain_head c WHERE c.org_id = org AND c.seq >= e.seq
                             ORDER BY c.seq, c.anchored_at LIMIT 5) h));
    IF p_show_contact OR p_show_page_url THEN
        SELECT c.wrapped_key, c.key_version INTO k FROM consentvault.contact_key c WHERE c.org_id = org AND c.contact_fp = e.contact_fp;
        IF FOUND THEN
            out := out || jsonb_build_object('contact_key', jsonb_build_object('wrapped_hex', encode(k.wrapped_key, 'hex'),
                                                                               'key_version', k.key_version));
            IF p_show_contact THEN
                out := out || jsonb_build_object('contact_ct_hex', encode(e.contact_ct, 'hex'));
            END IF;
            IF p_show_page_url AND e.page_url_ct IS NOT NULL THEN
                out := out || jsonb_build_object('page_url_ct_hex', encode(e.page_url_ct, 'hex'));
            END IF;
        END IF;
    END IF;
    IF p_post IS NOT NULL THEN
        SELECT * INTO pr FROM consentvault.raw_post WHERE org_id = org AND post_id = p_post;
        IF FOUND THEN
            post := jsonb_build_object(
                'org_id', pr.org_id, 'post_id', pr.post_id, 'seq', pr.seq, 'intake', pr.intake, 'received_at', pr.received_at,
                'method', pr.method, 'path', pr.path, 'path_ct_sha256', encode(sha256(pr.path_ct), 'hex'),
                'body_object_sha256', pr.body_object_sha256, 'facts_sha256', pr.facts_sha256,
                'query_ct_sha256', encode(sha256(pr.query_ct), 'hex'), 'headers_ct_sha256', encode(sha256(pr.headers_ct), 'hex'),
                'body_ct_sha256', CASE WHEN pr.body_ct IS NULL THEN NULL ELSE encode(sha256(pr.body_ct), 'hex') END,
                'body_object_id', pr.body_object_id, 'body_bytes', pr.body_bytes, 'body_sha256', pr.body_sha256,
                'unusual_size', pr.unusual_size, 'edge_received_at', pr.edge_received_at,
                'headers_presented_by', pr.headers_presented_by, 'kind', pr.kind, 'encryption', pr.encryption,
                'prev_hash', pr.prev_hash, 'row_hash', pr.row_hash, 'hash_version', pr.hash_version,
                'key', (SELECT jsonb_build_object('wrapped_hex', encode(q.post_key_wrapped, 'hex'), 'key_version', q.key_version)
                          FROM consentvault.raw_post_key q WHERE q.org_id = org AND q.post_id = p_post),
                'readings', (SELECT coalesce(jsonb_agg(jsonb_build_object('field', f.field, 'map_version', f.map_version,
                                   'state', f.state, 'values_ct_hex', CASE WHEN f.values_ct IS NULL THEN NULL ELSE encode(f.values_ct, 'hex') END,
                                   'extractor_version', f.extractor_version, 'occurrences', f.occurrences) ORDER BY f.field), '[]'::jsonb)
                               FROM (SELECT DISTINCT ON (r.field) r.* FROM consentvault.raw_post_field r
                                      WHERE r.org_id = org AND r.post_id = p_post
                                        AND r.field = ANY (ARRAY['consent', 'decision_time', 'wording', 'wording_hash',
                                                                 'trustedform_cert', 'jornaya_token'])
                                      ORDER BY r.field, r.map_version) f),
                'seals', (SELECT coalesce(jsonb_agg(jsonb_build_object('seal_id', z.seal_uuid, 'hash_version', z.hash_version,
                                   'columns', to_jsonb(z.columns), 'digest_hex', encode(z.digest, 'hex'), 'tsa_url', z.tsa_url,
                                   'gen_time', z.gen_time, 'token_hex', encode(z.token, 'hex')) ORDER BY z.created_at, z.seal_uuid), '[]'::jsonb)
                            FROM consentvault.raw_post_seal z WHERE z.org_id = org AND z.post_id = p_post));
            -- The body holds the contact point, usually the page address, and whatever else the form posted. It leaves only when the link
            -- shows both the contact point and the page address; otherwise the post's hash and seal are all a link carries of it.
            IF p_show_contact AND p_show_page_url AND pr.body_ct IS NOT NULL THEN
                post := post || jsonb_build_object('body_ct_hex', encode(pr.body_ct, 'hex'));
            END IF;
            out := out || jsonb_build_object('post', post);
        END IF;
    END IF;
    RETURN out;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_link_material(uuid, uuid, boolean, boolean, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.record_link_material(uuid, uuid, boolean, boolean, boolean) TO consentvault_app;

-- 8. The one function the public login may run ------------------------------------------------------------------------------------
-- p_kind: 'match_context' answers the organisation and its phone region (the application needs both to work out a fingerprint) and
-- writes nothing; 'page' and 'file' read the record and write one view fact (past the daily cap a counter row instead, and the answer is the
-- same); 'match' compares a fingerprint the application worked out from what the visitor typed with the record's own, answers yes
-- or no, and writes one fact that holds neither the fingerprint nor the contact. The 11th match in 24 hours, counted since the
-- sender's last reset, answers 'locked' whatever the contact. A link that does not exist, or whose digest is malformed, answers
-- exactly {"status": "not_found"}. A withdrawn link answers {"status": "withdrawn"}.
CREATE FUNCTION consentvault.public_proof_view(p_digest text, p_kind text DEFAULT 'page', p_candidate_fp text DEFAULT NULL) RETURNS jsonb
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    view_cap  constant integer := 1000;
    match_cap constant integer := 10;
    org       uuid;
    prior     text := pg_catalog.current_setting('consentvault.org_token', true);
    s         consentvault.proof_share;
    mat       jsonb;
    answer    jsonb;
    since     timestamptz;
    n         bigint;
    fp        text;
BEGIN
    IF p_kind IS NULL OR p_kind NOT IN ('page', 'file', 'match', 'match_context') THEN
        RAISE EXCEPTION 'consentvault public_proof_view: kind is page, file, match or match_context' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_digest IS NULL OR p_digest !~ '^[0-9a-f]{64}$' THEN
        RETURN jsonb_build_object('status', 'not_found');
    END IF;
    org := consentvault.proof_share_org(p_digest);
    IF org IS NULL THEN
        RETURN jsonb_build_object('status', 'not_found');
    END IF;
    PERFORM pg_catalog.set_config('consentvault.org_token', consentvault.sign_org_token(org, ARRAY['proof_read'], NULL, 60), true);
    SELECT * INTO s FROM consentvault.proof_share WHERE org_id = org AND link_digest = p_digest;
    IF NOT FOUND THEN
        answer := jsonb_build_object('status', 'not_found');
    ELSIF EXISTS (SELECT 1 FROM consentvault.proof_share_revocation r WHERE r.org_id = s.org_id AND r.share_id = s.share_id) THEN
        answer := jsonb_build_object('status', 'withdrawn');
    ELSE
        PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('consentvault.proof_share'), pg_catalog.hashtext(s.share_id::pg_catalog.text));
        IF p_kind = 'match_context' THEN
            -- what the application needs to work out a fingerprint (the organisation and its phone region); writes nothing
            IF NOT s.allow_contact_match THEN
                answer := jsonb_build_object('status', 'not_found');
            ELSE
                answer := jsonb_build_object('status', 'ok', 'org_id', s.org_id,
                                             'region', (SELECT g.default_region FROM consentvault.organization g WHERE g.org_id = s.org_id));
            END IF;
        ELSIF p_kind = 'match' THEN
            IF NOT s.allow_contact_match OR p_candidate_fp IS NULL OR p_candidate_fp !~ '^[0-9a-f]{64}$' THEN
                answer := jsonb_build_object('status', 'not_found');
            ELSE
                SELECT greatest(pg_catalog.clock_timestamp() - interval '24 hours',
                                coalesce((SELECT max(r.reset_at) FROM consentvault.proof_share_reset r
                                           WHERE r.org_id = s.org_id AND r.share_id = s.share_id), '-infinity'::timestamptz))
                  INTO since;
                SELECT count(*) INTO n FROM consentvault.proof_share_view v
                 WHERE v.org_id = s.org_id AND v.share_id = s.share_id AND v.kind IN ('match_yes', 'match_no') AND v.viewed_at > since;
                IF n >= match_cap THEN
                    IF (SELECT count(*) FROM consentvault.proof_share_view v WHERE v.org_id = s.org_id AND v.share_id = s.share_id
                           AND v.kind = 'match_locked' AND v.viewed_at > pg_catalog.clock_timestamp() - interval '24 hours') < view_cap THEN
                        INSERT INTO consentvault.proof_share_view (org_id, share_id, kind) VALUES (s.org_id, s.share_id, 'match_locked');
                    ELSE
                        INSERT INTO consentvault.proof_share_daily_count (org_id, share_id) VALUES (s.org_id, s.share_id);
                    END IF;
                    answer := jsonb_build_object('status', 'locked');
                ELSE
                    SELECT e.contact_fp INTO fp FROM consentvault.event e WHERE e.org_id = s.org_id AND e.event_id = s.event_id;
                    IF fp = p_candidate_fp THEN
                        INSERT INTO consentvault.proof_share_view (org_id, share_id, kind) VALUES (s.org_id, s.share_id, 'match_yes');
                        answer := jsonb_build_object('status', 'ok', 'match', 'yes');
                    ELSE
                        INSERT INTO consentvault.proof_share_view (org_id, share_id, kind) VALUES (s.org_id, s.share_id, 'match_no');
                        answer := jsonb_build_object('status', 'ok', 'match', 'no');
                    END IF;
                END IF;
            END IF;
        ELSE
            mat := consentvault.record_link_material(s.event_id, s.raw_post_id, s.show_contact, s.show_page_url, s.show_org_name);
            IF mat IS NULL THEN
                answer := jsonb_build_object('status', 'not_found');
            ELSE
                IF (SELECT count(*) FROM consentvault.proof_share_view v WHERE v.org_id = s.org_id AND v.share_id = s.share_id
                       AND v.kind IN ('page', 'file') AND v.viewed_at > pg_catalog.clock_timestamp() - interval '24 hours') < view_cap THEN
                    INSERT INTO consentvault.proof_share_view (org_id, share_id, kind) VALUES (s.org_id, s.share_id, p_kind);
                ELSE
                    INSERT INTO consentvault.proof_share_daily_count (org_id, share_id) VALUES (s.org_id, s.share_id);
                END IF;
                answer := jsonb_build_object('status', 'ok', 'material', mat || jsonb_build_object('flags', jsonb_build_object(
                    'show_org_name', s.show_org_name, 'show_contact', s.show_contact, 'allow_contact_match', s.allow_contact_match,
                    'show_page_url', s.show_page_url, 'show_bot_check', s.show_bot_check)));
            END IF;
        END IF;
    END IF;
    PERFORM pg_catalog.set_config('consentvault.org_token', coalesce(prior, ''), true);
    RETURN answer;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.public_proof_view(text, text, text) FROM PUBLIC;
GRANT USAGE ON SCHEMA consentvault TO consentvault_public_verify;
GRANT EXECUTE ON FUNCTION consentvault.public_proof_view(text, text, text) TO consentvault_public_verify;

-- 9. Erasure withdraws every link for the contact, in the transaction that destroys the key -----------------------------------
-- The body of 0054's erase_contact plus the statement marked below; nothing else changes.
CREATE OR REPLACE FUNCTION consentvault.erase_contact(p_contact_fp text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.lifecycle_lock();
    h   uuid;
    n   integer;
    hit uuid[];
BEGIN
    IF p_contact_fp IS NULL OR p_contact_fp !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'consentvault erase: the fingerprint must be 64 hex characters' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF NOT coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'worker:restore'], false) THEN
        RAISE EXCEPTION 'consentvault erase: an admin or restore token is required' USING ERRCODE = 'insufficient_privilege';
    END IF;
    h := consentvault.legal_hold_covering(p_contact_fp);
    IF h IS NOT NULL THEN
        RAISE EXCEPTION 'legal_hold_active:%', h USING ERRCODE = 'integrity_constraint_violation',
            DETAIL = 'a legal hold covers this contact; its key is not deleted';
    END IF;
    DELETE FROM consentvault.contact_key k WHERE k.org_id = org AND k.contact_fp = p_contact_fp;
    GET DIAGNOSTICS n = ROW_COUNT;
    -- Record links (competitive-builds, Build 1): every link to a record of this contact is withdrawn here, so a link never outlives
    -- the key. A link already withdrawn keeps its first withdrawal.
    INSERT INTO consentvault.proof_share_revocation (org_id, share_id, revoked_by, reason)
    SELECT s.org_id, s.share_id, 'erasure', 'erasure'
      FROM consentvault.proof_share s
      JOIN consentvault.event ev ON ev.org_id = s.org_id AND ev.event_id = s.event_id
     WHERE s.org_id = org AND ev.contact_fp = p_contact_fp
    ON CONFLICT (org_id, share_id) DO NOTHING;
    DELETE FROM consentvault.record_display d
     USING consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND d.org_id = r.org_id AND d.record_id = r.record_id;
    UPDATE consentvault.record_index i SET mask_ct = NULL
      FROM consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND i.org_id = r.org_id AND i.record_id = r.record_id
       AND i.mask_ct IS NOT NULL;
    UPDATE consentvault.record SET erased_at = clock_timestamp()
     WHERE org_id = org AND contact_fp = p_contact_fp AND erased_at IS NULL;
    -- Records list exports (records.md section 7): an export that holds a record of this contact point is destroyed in this
    -- transaction. It is marked expired, its links are revoked and its data key is destroyed, so the stored file, which may sit
    -- under retention and cannot be counted on to delete, can no longer be opened by anyone.
    PERFORM pg_advisory_xact_lock(hashtext('records_export_shred:' || org::text));
    SELECT coalesce(array_agg(DISTINCT m.export_id), '{}') INTO hit
      FROM consentvault.record_export_record m
      JOIN consentvault.record r ON r.org_id = m.org_id AND r.record_id = m.record_id
     WHERE m.org_id = org AND r.contact_fp = p_contact_fp;
    UPDATE consentvault.record_export e
       SET status = 'expired', expires_at = least(coalesce(e.expires_at, clock_timestamp()), clock_timestamp())
     WHERE e.org_id = org AND e.export_id = ANY (hit) AND e.status IN ('building', 'ready');
    UPDATE consentvault.record_export_link l SET revoked_at = clock_timestamp()
     WHERE l.org_id = org AND l.export_id = ANY (hit) AND l.revoked_at IS NULL;
    UPDATE consentvault.record_export_key k SET wrapped = NULL, destroyed_at = clock_timestamp()
     WHERE k.org_id = org AND k.export_id = ANY (hit) AND k.destroyed_at IS NULL;
    -- Confirmation messages (confirmations.md section 7): no sealed number survives the erasure of its contact. Queued sends to the
    -- contact are cancelled, every reply intent loses its sealed destination and text, and what the contact wrote from a number
    -- that was kept under the organization's display key is deleted, all in this transaction.
    UPDATE consentvault.confirmation_send_intent
       SET status = 'skipped', skip_reason = 'contact_erased', next_attempt_at = NULL, at = clock_timestamp()
     WHERE org_id = org AND contact_fp = p_contact_fp AND status = 'intent';
    UPDATE consentvault.confirmation_send_intent SET dest_ct = NULL, body_ct = NULL
     WHERE org_id = org AND contact_fp = p_contact_fp AND (dest_ct IS NOT NULL OR body_ct IS NOT NULL);
    DELETE FROM consentvault.confirmation_reply WHERE org_id = org AND from_fp = p_contact_fp AND key_kind = 'org';
    DELETE FROM consentvault.confirmation_connect_test WHERE org_id = org AND from_fp = p_contact_fp;
    RETURN n > 0;
END;
$$;
