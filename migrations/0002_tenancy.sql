-- Tenancy: many organisations in one vault, each isolated by row-level security.
--
-- A self-hoster running one company sees one organisation (the "home" organisation this migration creates for the
-- rows already in the ledger) and nothing else changes: with the vault in single mode and no tenant token set,
-- consentvault.current_org() answers the home organisation. Switching to multi mode (consentvault.enable_multi_tenant(),
-- owner only, one way) makes every tenant table answer only to a valid signed tenant token.
--
-- The tenant setting cannot be forged. The transaction-local setting consentvault.org_token holds the signed token
-- itself; current_org() checks its HMAC under a key kept in an owner-only table and its expiry, and answers NULL for
-- anything else. Policies compare org_id with (SELECT consentvault.current_org()), so a caller that writes the setting
-- by hand, forgets it, or replays an expired one sees no rows and can write none.
--
-- Clear contact points (hash version 1) stay legal only in the home organisation. Every other organisation stores a
-- keyed fingerprint and ciphertexts under a per-contact data key (hash version 2), so deleting one contact_key row
-- shreds that person.
--
-- Every function pins its search path to pg_catalog, pg_temp and names every table by schema; operators and functions
-- are never looked up in pg_temp, so nothing a caller plants is picked up.

-- Roles ------------------------------------------------------------------------------------------------------------
-- consentvault_operator: BYPASSRLS, owns the narrow cross-organisation lookups and may read non-personal columns only.
-- consentvault_worker:   may list active organisations for a named job (worker tokens) and sweep the replay guard.
-- Both are cluster-wide group roles made beforehand by a superuser (docker/initdb/10-roles.sh), which also grants
-- consentvault_operator to the owner so this migration can hand it function ownership.
--
-- The owner must be neither a superuser nor BYPASSRLS: FORCE ROW LEVEL SECURITY binds the owner, and every
-- SECURITY DEFINER function below runs as the owner, so an owner that bypasses row security would turn each of those
-- functions into a cross-organisation path. The migration refuses such an owner.
DO $$
DECLARE
    me record;
BEGIN
    SELECT rolsuper, rolbypassrls INTO me FROM pg_roles WHERE rolname = current_user;
    IF me.rolsuper OR me.rolbypassrls THEN
        RAISE EXCEPTION 'consentvault tenancy: refusing to migrate as %, a superuser or BYPASSRLS role; migrate as the schema owner (never a superuser, never BYPASSRLS)', current_user;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_operator' AND rolbypassrls) THEN
        RAISE EXCEPTION 'consentvault tenancy: role consentvault_operator (NOLOGIN BYPASSRLS) is missing; a superuser must run: CREATE ROLE consentvault_operator NOLOGIN BYPASSRLS; GRANT consentvault_operator TO %', current_user;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_worker') THEN
        RAISE EXCEPTION 'consentvault tenancy: role consentvault_worker is missing; a superuser must run: CREATE ROLE consentvault_worker NOLOGIN';
    END IF;
    IF NOT pg_has_role(current_user, 'consentvault_operator', 'SET') THEN
        RAISE EXCEPTION 'consentvault tenancy: % must be able to hand functions to consentvault_operator; a superuser must run: GRANT consentvault_operator TO %', current_user, current_user;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('consentvault_app', 'consentvault_worker') AND rolbypassrls) THEN
        RAISE EXCEPTION 'consentvault tenancy: a runtime group role carries BYPASSRLS; remove it before migrating';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA consentvault TO consentvault_operator, consentvault_worker;

-- HMAC-SHA256 from the built-in sha256(), so no extension is needed.
CREATE FUNCTION consentvault.hmac_sha256(p_key bytea, p_msg bytea) RETURNS bytea
    LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    k    bytea := p_key;
    ipad bytea;
    opad bytea;
BEGIN
    IF length(k) > 64 THEN
        k := sha256(k);
    END IF;
    k := k || decode(repeat('00', 64 - length(k)), 'hex');
    ipad := k;
    opad := k;
    FOR i IN 0..63 LOOP
        ipad := set_byte(ipad, i, get_byte(k, i) # 54);
        opad := set_byte(opad, i, get_byte(k, i) # 92);
    END LOOP;
    RETURN sha256(opad || sha256(ipad || p_msg));
END;
$$;
REVOKE ALL ON FUNCTION consentvault.hmac_sha256(bytea, bytea) FROM PUBLIC;

-- Tenant hierarchy -------------------------------------------------------------------------------------------------
CREATE TABLE consentvault.organization (
    org_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'offboarding', 'closed')),
    region     text,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Owner-only: the vault's tenancy mode and the home organisation that holds the single-company rows.
CREATE TABLE consentvault.tenancy_setting (
    singleton   boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    mode        text NOT NULL CHECK (mode IN ('single', 'multi')),
    home_org_id uuid NOT NULL REFERENCES consentvault.organization (org_id),
    changed_at  timestamptz NOT NULL DEFAULT now()
);

-- Owner-only: HMAC keys that sign tenant tokens. The runtime role cannot read this table.
CREATE TABLE consentvault.tenant_token_key (
    key_id     text PRIMARY KEY CHECK (key_id ~ '^[a-z0-9_-]{1,32}$'),
    secret     bytea NOT NULL CHECK (octet_length(secret) >= 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);

DO $$
DECLARE
    home uuid;
BEGIN
    INSERT INTO consentvault.organization (name) VALUES ('home') RETURNING org_id INTO home;
    INSERT INTO consentvault.tenancy_setting (mode, home_org_id) VALUES ('single', home);
END
$$;

-- The mode only moves from single to multi; the home organisation never changes.
CREATE FUNCTION consentvault.tenancy_setting_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' OR NEW.home_org_id <> OLD.home_org_id OR (OLD.mode = 'multi' AND NEW.mode <> 'multi') THEN
        RAISE EXCEPTION 'consentvault tenancy: the mode moves only from single to multi and the home organisation never changes'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER tenancy_setting_guard BEFORE UPDATE OR DELETE ON consentvault.tenancy_setting
    FOR EACH ROW EXECUTE FUNCTION consentvault.tenancy_setting_guard();
CREATE TRIGGER tenancy_setting_no_truncate BEFORE TRUNCATE ON consentvault.tenancy_setting
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- In single mode the vault holds exactly one organisation, the home one; a second is refused until the owner switches
-- to multi mode (otherwise a token-less caller, who is answered with the home organisation, would sit beside tenants).
CREATE FUNCTION consentvault.organization_single_mode_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (SELECT mode FROM consentvault.tenancy_setting WHERE singleton) IS DISTINCT FROM 'multi' THEN
        RAISE EXCEPTION 'consentvault tenancy: a second organisation needs multi mode (consentvault.enable_multi_tenant())'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER organization_single_mode_guard BEFORE INSERT ON consentvault.organization
    FOR EACH ROW EXECUTE FUNCTION consentvault.organization_single_mode_guard();

CREATE TABLE consentvault.brand (
    org_id       uuid NOT NULL REFERENCES consentvault.organization (org_id),
    brand_id     uuid NOT NULL DEFAULT gen_random_uuid(),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, brand_id)
);

CREATE TABLE consentvault.capture_source (
    org_id          uuid NOT NULL REFERENCES consentvault.organization (org_id),
    source_id       uuid NOT NULL DEFAULT gen_random_uuid(),
    kind            text NOT NULL CHECK (kind ~ '^[a-z][a-z_]{0,31}$'),
    brand_ids       uuid[] NOT NULL DEFAULT '{}',
    allowed_origins text[] NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, source_id)
);

-- A credential is a public key, an edge site key, or (fallback) an HMAC secret held only as ciphertext.
-- 'operator' is not a scope; capture credentials cannot read; read credentials cannot write; a site key never holds
-- capture_verified (the scope that may claim a verified contact point).
CREATE TABLE consentvault.credential (
    org_id        uuid NOT NULL REFERENCES consentvault.organization (org_id),
    credential_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    source_id     uuid,
    kind          text NOT NULL CHECK (kind IN ('jwt_public_key', 'edge_site_key', 'hmac_fallback')),
    alg           text CHECK (alg IN ('ES256', 'RS256', 'EdDSA')),
    public_key    text,
    secret_ct     bytea,
    scope         text[] NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz,
    PRIMARY KEY (org_id, credential_id),
    FOREIGN KEY (org_id, source_id) REFERENCES consentvault.capture_source (org_id, source_id),
    CONSTRAINT credential_scope_valid CHECK (
        cardinality(scope) > 0
        AND scope <@ ARRAY['capture', 'capture_verified', 'gate_read', 'proof_read', 'admin']::text[]
    ),
    CONSTRAINT credential_write_or_read CHECK (
        NOT (scope && ARRAY['capture', 'capture_verified']::text[] AND scope && ARRAY['gate_read', 'proof_read', 'admin']::text[])
    ),
    CONSTRAINT credential_site_key_not_verified CHECK (kind <> 'edge_site_key' OR NOT ('capture_verified' = ANY (scope))),
    CONSTRAINT credential_shape CHECK (
        (kind = 'jwt_public_key' AND public_key IS NOT NULL AND alg IS NOT NULL AND secret_ct IS NULL)
        OR (kind = 'edge_site_key' AND source_id IS NOT NULL AND secret_ct IS NULL AND alg IS NULL)
        OR (kind = 'hmac_fallback' AND secret_ct IS NOT NULL AND public_key IS NULL AND alg IS NULL)
    )
);

CREATE TABLE consentvault.member (
    org_id      uuid NOT NULL REFERENCES consentvault.organization (org_id),
    idp_issuer  text NOT NULL CHECK (length(idp_issuer) BETWEEN 1 AND 500),
    idp_subject text NOT NULL CHECK (length(idp_subject) BETWEEN 1 AND 500),
    role        text NOT NULL CHECK (role IN ('admin', 'compliance_viewer')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, idp_issuer, idp_subject)
);

-- Key references only; key material never enters the database.
CREATE TABLE consentvault.org_key (
    org_id        uuid NOT NULL REFERENCES consentvault.organization (org_id),
    version       integer NOT NULL CHECK (version >= 1),
    kms_key_ref   text NOT NULL,
    status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'scheduled_destroy', 'destroyed')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    destroy_after timestamptz,
    PRIMARY KEY (org_id, version)
);

-- One random data key per contact, wrapped by the org key, and the contact's salt encrypted under it. Deleting one row
-- shreds one person; no other row in the ledger is ever deleted.
CREATE TABLE consentvault.contact_key (
    org_id      uuid NOT NULL REFERENCES consentvault.organization (org_id),
    contact_fp  text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    wrapped_key bytea NOT NULL,
    key_version integer NOT NULL,
    salt_ct     bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, contact_fp),
    FOREIGN KEY (org_id, key_version) REFERENCES consentvault.org_key (org_id, version)
);
CREATE TRIGGER contact_key_no_update BEFORE UPDATE ON consentvault.contact_key
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER contact_key_no_truncate BEFORE TRUNCATE ON consentvault.contact_key
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Tenant functions -------------------------------------------------------------------------------------------------

-- The home organisation (holds the single-company rows). Not secret.
CREATE FUNCTION consentvault.home_org() RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT home_org_id FROM consentvault.tenancy_setting WHERE singleton;
$$;

-- Verify a token: 'v1.<key id>.<payload hex>.<hmac hex>', HMAC-SHA256 over 'v1.<key id>.<payload hex>'.
-- Answers one row (org_id, scopes, credential_id, expires_at) or no row. The payload is parsed only after the
-- signature checks, so a forged token is never parsed. A token that claims a life longer than 15 minutes is refused.
CREATE FUNCTION consentvault.verify_org_token(p_token text)
    RETURNS TABLE (org_id uuid, scopes text[], credential_id text, expires_at timestamptz)
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    parts   text[];
    k       bytea;
    want    bytea;
    payload jsonb;
    exp_at  timestamptz;
BEGIN
    IF p_token IS NULL OR length(p_token) > 4096 THEN
        RETURN;
    END IF;
    parts := string_to_array(p_token, '.');
    IF cardinality(parts) <> 4 OR parts[1] <> 'v1' OR parts[2] !~ '^[a-z0-9_-]{1,32}$'
       OR parts[3] !~ '^([0-9a-f]{2})+$' OR parts[4] !~ '^[0-9a-f]{64}$' THEN
        RETURN;
    END IF;
    SELECT secret INTO k FROM consentvault.tenant_token_key WHERE key_id = parts[2] AND retired_at IS NULL;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    want := consentvault.hmac_sha256(k, convert_to('v1.' || parts[2] || '.' || parts[3], 'UTF8'));
    IF sha256(want) <> sha256(decode(parts[4], 'hex')) THEN
        RETURN;
    END IF;
    payload := convert_from(decode(parts[3], 'hex'), 'UTF8')::jsonb;
    exp_at := to_timestamp((payload ->> 'exp')::bigint);
    IF exp_at <= statement_timestamp() OR exp_at > statement_timestamp() + interval '15 minutes' THEN
        RETURN;
    END IF;
    org_id := (payload ->> 'org')::uuid;
    scopes := ARRAY(SELECT jsonb_array_elements_text(payload -> 'scp'));
    credential_id := payload ->> 'cid';
    expires_at := exp_at;
    RETURN NEXT;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.verify_org_token(text) FROM PUBLIC;

-- The tenant every policy compares with. Valid token -> its org; no token in single mode -> the home org; anything
-- else (no token in multi mode, a forged, expired, malformed or retired-key token) -> NULL, which matches no row.
CREATE FUNCTION consentvault.current_org() RETURNS uuid
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    tok  text := current_setting('consentvault.org_token', true);
    st   record;
    v    record;
BEGIN
    IF tok IS NULL OR tok = '' THEN
        SELECT mode, home_org_id INTO st FROM consentvault.tenancy_setting WHERE singleton;
        IF FOUND AND st.mode = 'single' THEN
            RETURN st.home_org_id;
        END IF;
        RETURN NULL;
    END IF;
    SELECT * INTO v FROM consentvault.verify_org_token(tok);
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    RETURN v.org_id;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.current_org() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.current_org() TO consentvault_app, consentvault_worker;

-- The scopes of the current valid token (NULL when there is none).
CREATE FUNCTION consentvault.current_token_scopes() RETURNS text[]
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT v.scopes FROM consentvault.verify_org_token(
        nullif(pg_catalog.current_setting('consentvault.org_token', true), '')) v;
$$;
REVOKE ALL ON FUNCTION consentvault.current_token_scopes() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.current_token_scopes() TO consentvault_app, consentvault_worker;

-- Enter a tenant for the rest of the current transaction. Refuses (loudly) a token that does not verify.
CREATE FUNCTION consentvault.enter_org(p_token text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v record;
BEGIN
    SELECT * INTO v FROM consentvault.verify_org_token(p_token);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault tenant token refused: bad signature, unknown or retired key, expired, or malformed'
            USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    PERFORM set_config('consentvault.org_token', p_token, true);
    RETURN v.org_id;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.enter_org(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.enter_org(text) TO consentvault_app, consentvault_worker;

-- Sign a payload with the newest unretired key (owner only; used by dispatch_orgs).
CREATE FUNCTION consentvault.sign_org_token(p_org uuid, p_scopes text[], p_credential text, p_ttl_seconds integer)
    RETURNS text
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    kid     text;
    k       bytea;
    body    text;
BEGIN
    IF p_org IS NULL OR p_scopes IS NULL OR p_ttl_seconds IS NULL OR p_ttl_seconds < 1 OR p_ttl_seconds > 900 THEN
        RAISE EXCEPTION 'consentvault tenant token: org, scopes and a lifetime of 1 to 900 seconds are required'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT key_id, secret INTO kid, k FROM consentvault.tenant_token_key
     WHERE retired_at IS NULL ORDER BY created_at DESC, key_id LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault tenant token: no unretired signing key in consentvault.tenant_token_key'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    body := encode(convert_to(jsonb_build_object(
        'org', p_org::text, 'scp', to_jsonb(p_scopes), 'cid', p_credential,
        'iat', floor(extract(epoch FROM clock_timestamp()))::bigint,
        'exp', floor(extract(epoch FROM clock_timestamp()))::bigint + p_ttl_seconds,
        'jti', gen_random_uuid()::text)::text, 'UTF8'), 'hex');
    RETURN 'v1.' || kid || '.' || body || '.'
        || encode(consentvault.hmac_sha256(k, convert_to('v1.' || kid || '.' || body, 'UTF8')), 'hex');
END;
$$;
REVOKE ALL ON FUNCTION consentvault.sign_org_token(uuid, text[], text, integer) FROM PUBLIC;

-- Owner-only key management. The API holds the same secret to sign request tokens.
CREATE FUNCTION consentvault.install_token_key(p_key_id text, p_secret bytea) RETURNS void
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO consentvault.tenant_token_key (key_id, secret) VALUES (p_key_id, p_secret);
$$;
REVOKE ALL ON FUNCTION consentvault.install_token_key(text, bytea) FROM PUBLIC;

CREATE FUNCTION consentvault.retire_token_key(p_key_id text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE consentvault.tenant_token_key SET retired_at = now() WHERE key_id = p_key_id AND retired_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault tenant token: no unretired key %', p_key_id USING ERRCODE = 'no_data_found';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.retire_token_key(text) FROM PUBLIC;

-- Owner-only, one way: from here on every tenant table answers only to a valid token.
-- Also closes the single-company conveniences a tenant must not have:
-- * the bigserial ids of seal, chain_head, contact_log and review would count every tenant's rows, so their new
--   values become random and the runtime role loses the sequences and the SELECT on those columns (tenants use the
--   *_uuid columns);
-- * mark_seal_verified(bigint) is withdrawn in favour of mark_seal_verified(uuid).
CREATE FUNCTION consentvault.enable_multi_tenant() RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    t   text[];
    cols text;
BEGIN
    UPDATE consentvault.tenancy_setting SET mode = 'multi', changed_at = now() WHERE singleton AND mode = 'single';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault tenancy: the vault is already in multi mode'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    FOREACH t SLICE 1 IN ARRAY ARRAY[['seal', 'seal_id', 'seal_seal_id_seq'],
                                     ['chain_head', 'head_id', 'chain_head_head_id_seq'],
                                     ['contact_log', 'contact_log_id', 'contact_log_contact_log_id_seq'],
                                     ['review', 'review_id', 'review_review_id_seq']] LOOP
        EXECUTE format('REVOKE ALL ON SEQUENCE consentvault.%I FROM consentvault_app', t[3]);
        EXECUTE format('ALTER TABLE consentvault.%I ALTER COLUMN %I SET DEFAULT consentvault.random_internal_id()',
                       t[1], t[2]);
        SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position) INTO cols
          FROM information_schema.columns
         WHERE table_schema = 'consentvault' AND table_name = t[1] AND column_name <> t[2];
        EXECUTE format('REVOKE SELECT ON consentvault.%I FROM consentvault_app', t[1]);
        EXECUTE format('GRANT SELECT (%s) ON consentvault.%I TO consentvault_app', cols, t[1]);
    END LOOP;
    REVOKE EXECUTE ON FUNCTION consentvault.mark_seal_verified(bigint) FROM consentvault_app;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.enable_multi_tenant() FROM PUBLIC;

-- The cloud API calls this once at startup and refuses to serve unless it returns: a managed vault never runs in
-- single mode, where a caller with no token is answered with the home organisation.
CREATE FUNCTION consentvault.require_multi_tenant() RETURNS void
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (SELECT mode FROM consentvault.tenancy_setting WHERE singleton) IS DISTINCT FROM 'multi' THEN
        RAISE EXCEPTION 'consentvault tenancy: this vault is in single mode; a multi-tenant service must not serve it'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.require_multi_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.require_multi_tenant() TO consentvault_app, consentvault_worker;

-- A random positive 63-bit id for the internal bigint keys once tenants share the tables (no global count leaks).
CREATE FUNCTION consentvault.random_internal_id() RETURNS bigint
    LANGUAGE sql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
    SELECT (('x' || substr(md5(gen_random_uuid()::text), 1, 16))::bit(64)::bigint) & 9223372036854775807;
$$;

-- The ledger lock of one organisation. The home organisation keeps the single-company lock key, so every existing
-- writer (and anything else that takes hashtext('consentvault.ledger')) still serialises with it.
CREATE FUNCTION consentvault.ledger_lock_key(p_org uuid) RETURNS integer
    LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_org IS NULL THEN
        RAISE EXCEPTION 'consentvault ledger: no tenant entered (consentvault.current_org() is NULL)'
            USING ERRCODE = 'invalid_authorization_specification';
    END IF;
    IF p_org = consentvault.home_org() THEN
        RETURN hashtext('consentvault.ledger');
    END IF;
    RETURN hashtext('consentvault.ledger:' || p_org::text);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.ledger_lock_key(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.ledger_lock_key(uuid) TO consentvault_app, consentvault_worker;

-- Ledger tables gain org_id ---------------------------------------------------------------------------------------
DROP VIEW consentvault.current_permission;
DROP VIEW consentvault.unsealed_events;
DROP VIEW consentvault.chain_breaks;

-- Existing rows belong to the home organisation (a constant default fills them without firing any row trigger);
-- new rows default to the caller's tenant.
ALTER TABLE consentvault.event DROP CONSTRAINT event_disclosure_sha256_fkey;
ALTER TABLE consentvault.event DROP CONSTRAINT event_release_of_event_id_fkey;
ALTER TABLE consentvault.seal DROP CONSTRAINT seal_event_id_fkey;
ALTER TABLE consentvault.review DROP CONSTRAINT review_event_id_fkey;

DO $$
DECLARE
    home uuid := consentvault.home_org();
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['event', 'disclosure', 'contact_salt', 'seal', 'chain_head', 'contact_log', 'review'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ADD COLUMN org_id uuid NOT NULL DEFAULT %L', t, home);
        EXECUTE format('ALTER TABLE consentvault.%I ALTER COLUMN org_id SET DEFAULT consentvault.current_org()', t);
        EXECUTE format('ALTER TABLE consentvault.%I ADD CONSTRAINT %I FOREIGN KEY (org_id) REFERENCES consentvault.organization (org_id)',
                       t, t || '_org_fkey');
    END LOOP;
END
$$;

-- Wording is keyed per organisation: two tenants may register the same wording, and neither learns the other did.
-- (disclosure.register conflicts on (org_id, sha256).)
ALTER TABLE consentvault.disclosure DROP CONSTRAINT disclosure_pkey;
ALTER TABLE consentvault.disclosure ADD PRIMARY KEY (org_id, sha256);

ALTER TABLE consentvault.contact_salt DROP CONSTRAINT contact_salt_pkey;
ALTER TABLE consentvault.contact_salt ADD PRIMARY KEY (org_id, contact_norm);

ALTER TABLE consentvault.event DROP CONSTRAINT event_pkey;
ALTER TABLE consentvault.event ADD PRIMARY KEY (org_id, seq);
ALTER TABLE consentvault.event ADD CONSTRAINT event_org_event_id_key UNIQUE (org_id, event_id);
-- Event ids and row hashes are unique per organisation, never across: a global key would let one tenant probe for
-- another's ids by colliding with them.
ALTER TABLE consentvault.event DROP CONSTRAINT event_event_id_key;
ALTER TABLE consentvault.event DROP CONSTRAINT event_row_hash_key;
ALTER TABLE consentvault.event ADD CONSTRAINT event_org_row_hash_key UNIQUE (org_id, row_hash);

ALTER TABLE consentvault.event
    ALTER COLUMN contact_norm DROP NOT NULL,
    ALTER COLUMN contact_salt DROP NOT NULL,
    ALTER COLUMN subject_key DROP NOT NULL,
    ADD COLUMN contact_fp      text CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    ADD COLUMN contact_ct      bytea,
    ADD COLUMN subject_key_ct  bytea,
    ADD COLUMN subject_fp      text CHECK (subject_fp ~ '^[0-9a-f]{64}$'),
    ADD COLUMN subject_commit  text CHECK (subject_commit ~ '^[0-9a-f]{64}$'),
    ADD COLUMN evidence_sha256 text CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN key_version     integer,
    ADD COLUMN source_id       uuid,
    ADD COLUMN brand_ids       uuid[],
    ADD COLUMN page_url_ct     bytea,
    ADD COLUMN client_ip_ct    bytea,
    ADD COLUMN user_agent_ct   bytea,
    ADD COLUMN session_ref_ct  bytea,
    ADD COLUMN attribution_ct  bytea,
    ADD CONSTRAINT event_disclosure_org_fkey FOREIGN KEY (org_id, disclosure_sha256)
        REFERENCES consentvault.disclosure (org_id, sha256),
    ADD CONSTRAINT event_release_of_org_fkey FOREIGN KEY (org_id, release_of_event_id)
        REFERENCES consentvault.event (org_id, event_id),
    ADD CONSTRAINT event_source_org_fkey FOREIGN KEY (org_id, source_id)
        REFERENCES consentvault.capture_source (org_id, source_id),
    -- Hash version 1: clear contact point and salt (home organisation only, see check_clear_contact_home_only).
    -- Hash version 2: keyed fingerprints, ciphertexts and stored digests; no clear personal column.
    ADD CONSTRAINT event_shape_by_hash_version CHECK (
        (hash_version = 1 AND contact_norm IS NOT NULL AND contact_salt IS NOT NULL AND subject_key IS NOT NULL
            AND contact_fp IS NULL AND contact_ct IS NULL AND subject_key_ct IS NULL AND subject_fp IS NULL
            AND subject_commit IS NULL
            AND evidence_sha256 IS NULL AND key_version IS NULL AND source_id IS NULL AND brand_ids IS NULL
            AND page_url_ct IS NULL AND client_ip_ct IS NULL AND user_agent_ct IS NULL AND session_ref_ct IS NULL
            AND attribution_ct IS NULL)
        OR (hash_version = 2 AND contact_norm IS NULL AND contact_salt IS NULL AND subject_key IS NULL
            AND page_url IS NULL AND client_ip IS NULL AND user_agent IS NULL AND session_ref IS NULL
            AND contact_fp IS NOT NULL AND contact_ct IS NOT NULL AND subject_key_ct IS NOT NULL AND subject_fp IS NOT NULL
            AND subject_commit IS NOT NULL AND evidence_sha256 IS NOT NULL AND key_version IS NOT NULL
            AND brand_ids IS NOT NULL)
    );
CREATE INDEX event_org_contact_fp_idx ON consentvault.event (org_id, contact_fp) WHERE contact_fp IS NOT NULL;

ALTER TABLE consentvault.seal
    ADD COLUMN seal_uuid uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    ADD CONSTRAINT seal_event_org_fkey FOREIGN KEY (org_id, event_id) REFERENCES consentvault.event (org_id, event_id);

ALTER TABLE consentvault.chain_head
    ADD COLUMN head_uuid uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE;

ALTER TABLE consentvault.contact_log
    ALTER COLUMN contact_norm DROP NOT NULL,
    ADD COLUMN contact_log_uuid uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    ADD COLUMN contact_fp text CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    ADD COLUMN contact_ct bytea,
    ADD CONSTRAINT contact_log_contact_shape CHECK (
        (contact_norm IS NOT NULL AND contact_fp IS NULL AND contact_ct IS NULL)
        OR (contact_norm IS NULL AND contact_fp IS NOT NULL AND contact_ct IS NOT NULL)
    );
CREATE INDEX contact_log_org_fp_idx ON consentvault.contact_log (org_id, contact_fp, contacted_at) WHERE contact_fp IS NOT NULL;

ALTER TABLE consentvault.review
    ALTER COLUMN contact_norm DROP NOT NULL,
    ADD COLUMN review_uuid uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    ADD COLUMN contact_fp text CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    ADD COLUMN contact_ct bytea,
    ADD COLUMN message_ct bytea,
    ADD CONSTRAINT review_event_org_fkey FOREIGN KEY (org_id, event_id) REFERENCES consentvault.event (org_id, event_id),
    ADD CONSTRAINT review_contact_shape CHECK (
        (contact_norm IS NOT NULL AND contact_fp IS NULL AND contact_ct IS NULL AND message_ct IS NULL)
        OR (contact_norm IS NULL AND message IS NULL AND contact_fp IS NOT NULL AND contact_ct IS NOT NULL)
    );

-- Clear contact points are kept only for the home organisation.
CREATE FUNCTION consentvault.check_clear_contact_home_only() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (to_jsonb(NEW) ->> 'contact_norm') IS NOT NULL AND NEW.org_id IS DISTINCT FROM consentvault.home_org() THEN
        RAISE EXCEPTION 'consentvault tenancy: consentvault.% keeps a clear contact point only for the home organisation; store a fingerprint and ciphertext (hash version 2)', TG_TABLE_NAME
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (to_jsonb(NEW) ->> 'contact_norm') IS NOT NULL
       AND (SELECT mode FROM consentvault.tenancy_setting WHERE singleton) = 'multi' THEN
        RAISE EXCEPTION 'consentvault tenancy: in multi mode no row keeps a clear contact point (consentvault.%); write hash version 2', TG_TABLE_NAME
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER event_clear_contact_home_only BEFORE INSERT ON consentvault.event
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_clear_contact_home_only();
CREATE TRIGGER contact_salt_clear_contact_home_only BEFORE INSERT ON consentvault.contact_salt
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_clear_contact_home_only();
CREATE TRIGGER contact_log_clear_contact_home_only BEFORE INSERT ON consentvault.contact_log
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_clear_contact_home_only();
CREATE TRIGGER review_clear_contact_home_only BEFORE INSERT OR UPDATE ON consentvault.review
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_clear_contact_home_only();

-- A verified contact point (one-time code or inbound keyword) is the only thing that lets a grant lift the person's
-- own stop, so claiming one needs the capture_verified scope on the tenant token. Site keys and connected-system
-- signal credentials never hold that scope. A write with no token at all is the single-company path (home org).
CREATE FUNCTION consentvault.check_verified_claim() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    scopes pg_catalog.text[];
BEGIN
    IF NEW.contact_verification OPERATOR(pg_catalog.=) 'none'
       OR COALESCE(pg_catalog.current_setting('consentvault.org_token', true), '') OPERATOR(pg_catalog.=) '' THEN
        RETURN NEW;
    END IF;
    scopes := consentvault.current_token_scopes();
    IF scopes IS NULL OR NOT ('capture_verified' OPERATOR(pg_catalog.=) ANY (scopes)) THEN
        RAISE EXCEPTION 'consentvault verified contact: claiming a verified contact point needs the capture_verified scope'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER event_verified_claim BEFORE INSERT ON consentvault.event
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_verified_claim();

-- Ledger guards, now per organisation ------------------------------------------------------------------------------

-- Fork guard: an insert must extend its organisation's head, under that organisation's ledger lock. Genesis per org.
CREATE OR REPLACE FUNCTION consentvault.check_chain_head() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    head_seq  pg_catalog.int8;
    head_hash pg_catalog.text;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(consentvault.ledger_lock_key(NEW.org_id));
    SELECT seq, row_hash INTO head_seq, head_hash FROM consentvault.event
     WHERE org_id OPERATOR(pg_catalog.=) NEW.org_id ORDER BY seq DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.seq OPERATOR(pg_catalog.<>) 1
           OR NEW.prev_hash OPERATOR(pg_catalog.<>) pg_catalog.repeat('0', 64) THEN
            RAISE EXCEPTION 'consentvault chain: first event must have seq 1 and the genesis prev_hash'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF NEW.seq OPERATOR(pg_catalog.<>) (head_seq OPERATOR(pg_catalog.+) 1)
          OR NEW.prev_hash OPERATOR(pg_catalog.<>) head_hash THEN
        RAISE EXCEPTION 'consentvault chain: event does not extend the current head (expected seq %)',
            head_seq OPERATOR(pg_catalog.+) 1
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- Salt minting, per organisation, home organisation only (other organisations keep the salt under the contact key).
CREATE OR REPLACE FUNCTION consentvault.mint_contact_salt(p_contact_norm text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    held pg_catalog.bytea;
    org  pg_catalog.uuid := consentvault.current_org();
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(consentvault.ledger_lock_key(org));
    IF org OPERATOR(pg_catalog.<>) consentvault.home_org() THEN
        RAISE EXCEPTION 'consentvault contact salt: clear salts are kept only for the home organisation'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    SELECT salt INTO held FROM consentvault.contact_salt
     WHERE org_id OPERATOR(pg_catalog.=) org AND contact_norm OPERATOR(pg_catalog.=) p_contact_norm;
    IF NOT FOUND THEN
        held := pg_catalog.sha256(pg_catalog.convert_to(
            pg_catalog.gen_random_uuid()::pg_catalog.text OPERATOR(pg_catalog.||)
            pg_catalog.gen_random_uuid()::pg_catalog.text OPERATOR(pg_catalog.||)
            pg_catalog.gen_random_uuid()::pg_catalog.text, 'UTF8'));
        INSERT INTO consentvault.contact_salt (org_id, contact_norm, salt) VALUES (org, p_contact_norm, held);
    END IF;
    RETURN pg_catalog.encode(held, 'hex');
END;
$$;

-- Salt guard: a version-1 row carries its contact's salt; a version-2 row needs its contact's key row.
CREATE OR REPLACE FUNCTION consentvault.check_contact_salt() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    held pg_catalog.bytea;
BEGIN
    IF NEW.contact_norm IS NULL THEN
        PERFORM 1 FROM consentvault.contact_key
         WHERE org_id OPERATOR(pg_catalog.=) NEW.org_id AND contact_fp OPERATOR(pg_catalog.=) NEW.contact_fp;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'consentvault contact key: the row''s contact has no key in consentvault.contact_key'
                USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        RETURN NEW;
    END IF;
    SELECT salt INTO held FROM consentvault.contact_salt
     WHERE org_id OPERATOR(pg_catalog.=) NEW.org_id AND contact_norm OPERATOR(pg_catalog.=) NEW.contact_norm;
    IF NOT FOUND OR pg_catalog.encode(held, 'hex') OPERATOR(pg_catalog.<>) NEW.contact_salt THEN
        RAISE EXCEPTION 'consentvault contact salt: the row must carry the contact''s own salt'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION consentvault.check_grant_scope() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    d_channels pg_catalog.text[];
    d_purposes pg_catalog.text[];
BEGIN
    IF NEW.event_type OPERATOR(pg_catalog.<>) 'grant' THEN
        RETURN NEW;
    END IF;
    SELECT channels, purposes INTO d_channels, d_purposes FROM consentvault.disclosure
     WHERE org_id OPERATOR(pg_catalog.=) NEW.org_id AND sha256 OPERATOR(pg_catalog.=) NEW.disclosure_sha256;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault grant scope: disclosure % is not held', NEW.disclosure_sha256
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NOT (NEW.channels OPERATOR(pg_catalog.<@) d_channels AND NEW.purposes OPERATOR(pg_catalog.<@) d_purposes) THEN
        RAISE EXCEPTION 'consentvault grant scope: the grant names a channel or purpose its disclosure does not'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION consentvault.check_release_ref() RETURNS trigger LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    g_channels pg_catalog.text[];
    g_purposes pg_catalog.text[];
    g_verification pg_catalog.text;
BEGIN
    IF NEW.event_type OPERATOR(pg_catalog.<>) 'release' THEN
        RETURN NEW;
    END IF;
    SELECT g.channels, g.purposes, g.contact_verification INTO g_channels, g_purposes, g_verification
    FROM consentvault.event g
    WHERE g.org_id OPERATOR(pg_catalog.=) NEW.org_id
      AND g.event_id OPERATOR(pg_catalog.=) NEW.release_of_event_id
      AND g.event_type OPERATOR(pg_catalog.=) 'grant'
      AND g.origin OPERATOR(pg_catalog.=) 'consumer'
      AND g.contact_kind OPERATOR(pg_catalog.=) NEW.contact_kind
      AND g.contact_norm IS NOT DISTINCT FROM NEW.contact_norm
      AND g.contact_fp IS NOT DISTINCT FROM NEW.contact_fp
      AND g.seq OPERATOR(pg_catalog.<) NEW.seq;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault release: a release must decide an earlier consumer grant of the same contact point'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NOT (NEW.channels OPERATOR(pg_catalog.<@) g_channels AND NEW.purposes OPERATOR(pg_catalog.<@) g_purposes) THEN
        RAISE EXCEPTION 'consentvault release: a release may name only the channels and purposes of the grant it decides'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.release_outcome OPERATOR(pg_catalog.=) 'released'
       AND g_verification OPERATOR(pg_catalog.<>) ALL (ARRAY['otp', 'inbound_keyword']::pg_catalog.text[]) THEN
        RAISE EXCEPTION 'consentvault release: only a grant whose contact point was verified (one-time code or inbound keyword) can lift a stop'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- Pre-tenant lookups and worker dispatch ---------------------------------------------------------------------------
-- Owned by consentvault_operator (BYPASSRLS), which may read only the non-personal columns granted below. These are
-- the only cross-organisation reads the runtime role can make, one credential or one identity at a time.

-- A non-superuser owner can hand a function to another role only if that role may create in the schema; the grant
-- lasts only while the three functions below change hands.
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
GRANT SELECT (org_id, status) ON consentvault.organization TO consentvault_operator;
GRANT SELECT (org_id, credential_id, source_id, kind, alg, public_key, scope, revoked_at)
    ON consentvault.credential TO consentvault_operator;
GRANT SELECT (org_id, source_id, allowed_origins) ON consentvault.capture_source TO consentvault_operator;
GRANT SELECT (org_id, idp_issuer, idp_subject, role) ON consentvault.member TO consentvault_operator;

CREATE FUNCTION consentvault.resolve_credential(p_credential_id uuid)
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
ALTER FUNCTION consentvault.resolve_credential(uuid) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.resolve_credential(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.resolve_credential(uuid) TO consentvault_app;

CREATE FUNCTION consentvault.resolve_member(p_idp_issuer text, p_idp_subject text)
    RETURNS TABLE (org_id uuid, role text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT m.org_id, m.role
    FROM consentvault.member m
    JOIN consentvault.organization o ON o.org_id = m.org_id
    WHERE m.idp_issuer = p_idp_issuer AND m.idp_subject = p_idp_subject AND o.status = 'active'
    ORDER BY m.org_id;
$$;
ALTER FUNCTION consentvault.resolve_member(text, text) OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.resolve_member(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.resolve_member(text, text) TO consentvault_app;

CREATE FUNCTION consentvault.active_org_ids() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT org_id FROM consentvault.organization WHERE status = 'active' ORDER BY org_id;
$$;
ALTER FUNCTION consentvault.active_org_ids() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.active_org_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.active_org_ids() TO CURRENT_USER;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;

-- A short-lived (5 minute) worker token per active organisation for a named job; workers process one org at a time.
CREATE FUNCTION consentvault.dispatch_orgs(p_job text) RETURNS TABLE (org_id uuid, token text)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    o uuid;
BEGIN
    IF p_job IS NULL OR p_job !~ '^[a-z][a-z0-9_]{0,40}$' THEN
        RAISE EXCEPTION 'consentvault dispatch: job name must match ^[a-z][a-z0-9_]{0,40}$'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR o IN SELECT * FROM consentvault.active_org_ids() LOOP
        org_id := o;
        token := consentvault.sign_org_token(o, ARRAY['worker:' || p_job], NULL, 300);
        RETURN NEXT;
    END LOOP;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.dispatch_orgs(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.dispatch_orgs(text) TO consentvault_worker;

-- Row-level security on every tenant table; FORCE binds the table owner too -----------------------------------------
-- Every table: rows of the verified tenant only. Evidence tables (personal data, chain rows) additionally need a read
-- scope (gate_read, proof_read, admin) to SELECT: a capture token writes but cannot read back, a worker token reads
-- nothing here. The writer gets the two things it needs through owner functions (ledger_head, contact_key_of), and the
-- ledger guards run as the owner, still bound to current_org(). No token (single mode) reads as before.
-- The one intended cross-organisation path is dispatch_orgs: the worker role gets one short token per active
-- organisation and processes them one at a time; resolve_credential and resolve_member answer one identity at a time.
CREATE FUNCTION consentvault.may_read_evidence() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.event'::regclass)
        OR coalesce(current_setting('consentvault.org_token', true), '') = ''
        OR coalesce(consentvault.current_token_scopes() && ARRAY['gate_read', 'proof_read', 'admin'], false);
$$;
REVOKE ALL ON FUNCTION consentvault.may_read_evidence() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.may_read_evidence() TO consentvault_app, consentvault_worker;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['organization', 'brand', 'capture_source', 'credential', 'member', 'org_key', 'contact_key',
                             'event', 'disclosure', 'contact_salt', 'seal', 'chain_head', 'contact_log', 'review'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
    END LOOP;
    FOREACH t IN ARRAY ARRAY['event', 'contact_key', 'contact_salt', 'contact_log', 'review'] LOOP
        EXECUTE format('CREATE POLICY %I ON consentvault.%I AS RESTRICTIVE FOR SELECT'
                       ' USING ((SELECT consentvault.may_read_evidence()))', t || '_read_scope', t);
    END LOOP;
END
$$;

-- The writer's two reads, for any scope of the current tenant: the chain head (no personal data) and one contact's
-- wrapped key and encrypted salt (useless without the key service).
CREATE FUNCTION consentvault.ledger_head() RETURNS TABLE (seq bigint, row_hash text)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT e.seq, e.row_hash FROM consentvault.event e
     WHERE e.org_id = consentvault.current_org() ORDER BY e.seq DESC LIMIT 1;
$$;
REVOKE ALL ON FUNCTION consentvault.ledger_head() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.ledger_head() TO consentvault_app;

CREATE FUNCTION consentvault.contact_key_of(p_contact_fp text)
    RETURNS TABLE (wrapped_key bytea, key_version integer, salt_ct bytea)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT k.wrapped_key, k.key_version, k.salt_ct FROM consentvault.contact_key k
     WHERE k.org_id = consentvault.current_org() AND k.contact_fp = p_contact_fp;
$$;
REVOKE ALL ON FUNCTION consentvault.contact_key_of(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.contact_key_of(text) TO consentvault_app;

-- Seal verification stamps, scoped to the current tenant. The uuid form is the tenant interface; the 0001 bigint form
-- (single-company seal job) is narrowed to the current organisation and withdrawn by enable_multi_tenant().
CREATE OR REPLACE FUNCTION consentvault.mark_seal_verified(p_seal_id bigint) RETURNS void
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    UPDATE consentvault.seal SET verified_at = pg_catalog.now()
     WHERE seal_id OPERATOR(pg_catalog.=) p_seal_id AND org_id OPERATOR(pg_catalog.=) consentvault.current_org();
$$;

CREATE FUNCTION consentvault.mark_seal_verified(p_seal_uuid uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE consentvault.seal SET verified_at = now()
     WHERE seal_uuid = p_seal_uuid AND org_id = consentvault.current_org();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault seal: no seal % in the current organisation', p_seal_uuid
            USING ERRCODE = 'no_data_found';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.mark_seal_verified(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.mark_seal_verified(uuid) TO consentvault_app;

-- Views, partitioned by organisation; security_invoker so row-level security applies to the caller ------------------
CREATE VIEW consentvault.chain_breaks WITH (security_invoker = true) AS
SELECT seq, event_id,
       CASE WHEN expected_seq <> seq THEN 'seq_gap' ELSE 'prev_hash_mismatch' END AS reason,
       org_id
FROM (
    SELECT org_id, seq, event_id, prev_hash,
           coalesce(lag(seq) OVER w + 1, 1) AS expected_seq,
           coalesce(lag(row_hash) OVER w, repeat('0', 64)) AS expected_prev
    FROM consentvault.event
    WINDOW w AS (PARTITION BY org_id ORDER BY seq)
) t
WHERE expected_seq <> seq OR expected_prev <> prev_hash;

CREATE VIEW consentvault.unsealed_events WITH (security_invoker = true) AS
SELECT e.*
FROM consentvault.event e
WHERE NOT EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.org_id = e.org_id AND s.event_id = e.event_id);

-- Same rules as before, per organisation and per contact (clear contact point in the home organisation, keyed
-- fingerprint elsewhere; ckey is whichever the row holds: a fingerprint is 64 hex characters, a normalised phone
-- starts with '+' and an email holds '@', so the two never collide).
CREATE VIEW consentvault.current_permission WITH (security_invoker = true) AS
WITH exploded AS (
    SELECT e.org_id, e.contact_kind, e.contact_norm, e.contact_fp,
           coalesce(e.contact_fp, e.contact_norm) AS ckey,
           e.event_type,
           CASE WHEN e.event_type = 'release'
                THEN (SELECT g.seq FROM consentvault.event g
                       WHERE g.org_id = e.org_id AND g.event_id = e.release_of_event_id)
                ELSE e.seq END AS rk,
           ch AS channel, pu AS purpose,
           (e.event_type IN ('revoke', 'suppress')
              AND (e.origin <> 'consumer' OR e.method NOT IN ('keyword', 'checkbox', 'written'))) AS hard_stop,
           (e.event_type = 'release' AND e.origin = 'consumer' AND e.release_outcome = 'released') AS valid_release
    FROM consentvault.event e, unnest(e.channels) AS ch, unnest(e.purposes) AS pu
),
star AS (
    SELECT org_id, contact_kind, ckey, channel,
           max(rk) FILTER (WHERE event_type IN ('revoke', 'suppress')) AS star_stop_rk,
           max(rk) FILTER (WHERE hard_stop)                            AS star_hard_rk
    FROM exploded
    WHERE purpose = '*'
    GROUP BY org_id, contact_kind, ckey, channel
),
agg AS (
    SELECT x.org_id, x.contact_kind, x.ckey, x.contact_norm, x.contact_fp, x.channel, x.purpose,
           max(x.rk) FILTER (WHERE x.event_type = 'grant')                    AS grant_rk,
           greatest(max(x.rk) FILTER (WHERE x.event_type IN ('revoke', 'suppress')), s.star_stop_rk) AS stop_rk,
           greatest(max(x.rk) FILTER (WHERE x.hard_stop), s.star_hard_rk)      AS hard_stop_rk,
           max(x.rk) FILTER (WHERE x.valid_release)                           AS release_rk
    FROM exploded x
    LEFT JOIN star s USING (org_id, contact_kind, ckey, channel)
    GROUP BY x.org_id, x.contact_kind, x.ckey, x.contact_norm, x.contact_fp, x.channel, x.purpose,
             s.star_stop_rk, s.star_hard_rk
)
SELECT a.contact_kind, a.contact_norm, a.channel, a.purpose,
       (a.grant_rk IS NOT NULL AND a.hard_stop_rk IS NULL
            AND (a.stop_rk IS NULL OR coalesce(a.release_rk > a.stop_rk, false))) AS allowed,
       CASE
           WHEN a.stop_rk IS NOT NULL
                AND (a.hard_stop_rk IS NOT NULL OR a.release_rk IS NULL OR a.release_rk < a.stop_rk)
               THEN 'stopped:' || (SELECT event_type FROM consentvault.event
                                    WHERE org_id = a.org_id AND seq = a.stop_rk)
           WHEN a.grant_rk IS NULL THEN 'no_grant'
           ELSE 'granted'
       END AS reason,
       (SELECT event_id FROM consentvault.event
         WHERE org_id = a.org_id AND seq = greatest(a.grant_rk, a.stop_rk, a.release_rk)) AS deciding_event_id,
       a.org_id, a.contact_fp
FROM agg a;

-- Grants -----------------------------------------------------------------------------------------------------------
GRANT SELECT ON consentvault.chain_breaks, consentvault.unsealed_events, consentvault.current_permission TO consentvault_app;
GRANT SELECT ON consentvault.organization, consentvault.brand, consentvault.capture_source, consentvault.member,
    consentvault.org_key TO consentvault_app;
GRANT SELECT (org_id, credential_id, source_id, kind, alg, public_key, scope, created_at, revoked_at)
    ON consentvault.credential TO consentvault_app;
GRANT SELECT, INSERT ON consentvault.contact_key TO consentvault_app;
GRANT EXECUTE ON FUNCTION consentvault.home_org() TO consentvault_app, consentvault_worker;
