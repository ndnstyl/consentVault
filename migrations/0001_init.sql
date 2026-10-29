CREATE SCHEMA IF NOT EXISTS consentvault;

-- Roles. The role that runs this migration owns every object below (the owner). Day-to-day commands run as a
-- login role that is a MEMBER of the group role consentvault_app, which carries SELECT and INSERT only.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_app') THEN
        CREATE ROLE consentvault_app NOLOGIN;
    END IF;
END
$$;

REVOKE ALL ON SCHEMA consentvault FROM PUBLIC;
GRANT USAGE ON SCHEMA consentvault TO consentvault_app;
-- Nobody but the owner creates objects in the default schema, so no one can plant a function or operator there.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Exact consent wording, stored once by sha256 of the body.
CREATE TABLE consentvault.disclosure (
    sha256        text PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    body          text NOT NULL,
    label         text NOT NULL,
    locale        text NOT NULL,
    channels      text[] NOT NULL,
    purposes      text[] NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT disclosure_channels_valid CHECK (
        cardinality(channels) > 0 AND channels <@ ARRAY['voice', 'artificial_voice', 'sms', 'email']::text[]
    ),
    CONSTRAINT disclosure_purposes_valid CHECK (
        cardinality(purposes) > 0
        AND array_to_string(purposes, ',') = lower(array_to_string(purposes, ','))
        AND NOT ('*' = ANY (purposes))
    )
);

-- The chained ledger. hash_version 1 digests every evidence column below (everything except prev_hash and row_hash).
-- received_at is the vault's own clock; edge_received_at is the capture edge's claimed receipt time (evidence only).
-- contact_commit is sha256(contact_salt || contact_norm). contact_salt is the contact's own random 32-byte salt
-- (64 hex characters), minted once into consentvault.contact_salt, copied into every row for that contact and
-- covered by the row hash; a trigger refuses a row whose salt is not the contact's. The chain link of every row
-- carries the commitment, so a bundle shows the chain without revealing anyone else's contact point (a phone
-- number cannot be tested against a commitment without the salt), while every link of one contact still shares one
-- commitment, so a verifier holding the subject's salt can find every link that is theirs.
CREATE TABLE consentvault.contact_salt (
    contact_norm text PRIMARY KEY,
    salt         bytea NOT NULL CHECK (octet_length(salt) = 32),
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE consentvault.event (
    seq                 bigint PRIMARY KEY CHECK (seq >= 1),
    event_id            uuid NOT NULL UNIQUE,
    subject_key         text NOT NULL,
    contact_kind        text NOT NULL CHECK (contact_kind IN ('phone', 'email')),
    contact_norm        text NOT NULL,
    contact_salt        text NOT NULL CHECK (contact_salt ~ '^[0-9a-f]{64}$'),
    contact_commit      text NOT NULL CHECK (contact_commit ~ '^[0-9a-f]{64}$'),
    event_type          text NOT NULL CHECK (event_type IN ('grant', 'revoke', 'suppress', 'release')),
    channels            text[] NOT NULL,
    purposes            text[] NOT NULL,
    disclosure_sha256   text REFERENCES consentvault.disclosure (sha256),
    method              text NOT NULL CHECK (method IN ('checkbox', 'verbal', 'written', 'keyword', 'staff', 'import')),
    origin              text NOT NULL CHECK (origin IN ('consumer', 'staff', 'regulatory', 'import')),
    captured_at         timestamptz NOT NULL,
    received_at         timestamptz NOT NULL,
    edge_received_at    timestamptz,
    page_url            text,
    client_ip           text,
    user_agent          text,
    session_ref         text,
    bot_check           text,
    payload_sha256      text,
    source              text,
    recorded_by         text,
    release_of_event_id uuid REFERENCES consentvault.event (event_id),
    release_outcome     text,
    release_cause       text,
    contact_verification text NOT NULL DEFAULT 'none' CHECK (contact_verification IN ('none', 'otp', 'inbound_keyword')),
    hash_version        integer NOT NULL,
    prev_hash           text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    row_hash            text NOT NULL UNIQUE CHECK (row_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT event_channels_valid CHECK (
        cardinality(channels) > 0 AND channels <@ ARRAY['voice', 'artificial_voice', 'sms', 'email']::text[]
    ),
    CONSTRAINT event_purposes_valid CHECK (
        cardinality(purposes) > 0
        AND array_to_string(purposes, ',') = lower(array_to_string(purposes, ','))
        AND (NOT ('*' = ANY (purposes)) OR (event_type IN ('revoke', 'suppress') AND purposes = ARRAY['*']::text[]))
    ),
    CONSTRAINT event_grant_has_disclosure CHECK (event_type <> 'grant' OR disclosure_sha256 IS NOT NULL),
    CONSTRAINT event_contact_commit_matches CHECK (
        contact_commit = encode(sha256(convert_to(contact_salt || contact_norm, 'UTF8')), 'hex')
    ),
    CONSTRAINT event_captured_not_future CHECK ((captured_at - received_at) <= interval '5 minutes'),
    CONSTRAINT event_verification_only_on_grant CHECK (event_type = 'grant' OR contact_verification = 'none'),
    CONSTRAINT event_release_outcome_valid CHECK (release_outcome IS NULL OR release_outcome IN ('released', 'refused')),
    CONSTRAINT event_release_columns_shape CHECK (
        (event_type = 'release' AND release_of_event_id IS NOT NULL AND release_outcome IS NOT NULL
            AND ((release_outcome = 'refused') = (release_cause IS NOT NULL)))
        OR (event_type <> 'release' AND release_of_event_id IS NULL AND release_outcome IS NULL
            AND release_cause IS NULL)
    )
);
CREATE INDEX event_contact_idx ON consentvault.event (contact_kind, contact_norm);
CREATE INDEX event_subject_idx ON consentvault.event (subject_key);
CREATE INDEX event_release_of_idx ON consentvault.event (release_of_event_id) WHERE release_of_event_id IS NOT NULL;

-- contact_verification records how the integrator established that the person who ticked the box controls the
-- contact point: 'none' (a web form alone proves nothing about who owns the number or address), 'otp' (the integrator
-- confirmed a one-time code sent to the contact point) or 'inbound_keyword' (the contact point itself sent a START-type
-- message). The vault records what the integrator says it verified; running the code check is the integrator's job.
-- Only a grant verified one of those two ways can lift a consumer's own stop.

-- RFC 3161 timestamp seals. A seal names the columns and hash version it covers.
CREATE TABLE consentvault.seal (
    seal_id      bigserial PRIMARY KEY,
    event_id     uuid NOT NULL REFERENCES consentvault.event (event_id),
    hash_version integer NOT NULL,
    columns      text[] NOT NULL,
    digest       bytea NOT NULL CHECK (octet_length(digest) = 32),
    tsa_url      text NOT NULL,
    token        bytea NOT NULL,
    gen_time     timestamptz,
    verified_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX seal_event_idx ON consentvault.seal (event_id);

-- Anchors: the head of the chain at a moment, also written to an external sink by `consentvault anchor`.
CREATE TABLE consentvault.chain_head (
    head_id     bigserial PRIMARY KEY,
    seq         bigint NOT NULL CHECK (seq >= 1),
    row_hash    text NOT NULL CHECK (row_hash ~ '^[0-9a-f]{64}$'),
    sink        text,
    anchored_at timestamptz NOT NULL DEFAULT now()
);

-- Outbound attempts recorded by integrators.
CREATE TABLE consentvault.contact_log (
    contact_log_id bigserial PRIMARY KEY,
    contact_kind   text NOT NULL CHECK (contact_kind IN ('phone', 'email')),
    contact_norm   text NOT NULL,
    channel        text NOT NULL CHECK (channel IN ('voice', 'artificial_voice', 'sms', 'email')),
    purpose        text,
    contacted_at   timestamptz NOT NULL,
    outcome        text,
    ref            text,
    recorded_by    text,
    recorded_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX contact_log_contact_idx ON consentvault.contact_log (contact_kind, contact_norm, contacted_at);

-- Human review of ambiguous stop messages and pending releases.
CREATE TABLE consentvault.review (
    review_id    bigserial PRIMARY KEY,
    kind         text NOT NULL CHECK (kind IN ('stop_message', 'release')),
    contact_kind text NOT NULL CHECK (contact_kind IN ('phone', 'email')),
    contact_norm text NOT NULL,
    message      text,
    event_id     uuid REFERENCES consentvault.event (event_id),
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'resolved')),
    resolution   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    resolved_at  timestamptz,
    resolved_by  text
);

-- Append-only enforcement. Every function below pins its search path and names every function and operator by
-- schema, so an object planted in a schema the caller controls is never picked up.
CREATE FUNCTION consentvault.refuse_change() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'consentvault.% is append-only: % refused', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER event_append_only BEFORE UPDATE OR DELETE ON consentvault.event
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER event_no_truncate BEFORE TRUNCATE ON consentvault.event
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER contact_salt_append_only BEFORE UPDATE OR DELETE ON consentvault.contact_salt
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER contact_salt_no_truncate BEFORE TRUNCATE ON consentvault.contact_salt
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER disclosure_append_only BEFORE UPDATE OR DELETE ON consentvault.disclosure
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER disclosure_no_truncate BEFORE TRUNCATE ON consentvault.disclosure
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER chain_head_append_only BEFORE UPDATE OR DELETE ON consentvault.chain_head
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER chain_head_no_truncate BEFORE TRUNCATE ON consentvault.chain_head
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- A seal may only gain a verified_at stamp; every other column is frozen.
CREATE FUNCTION consentvault.seal_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.seal is append-only: DELETE refused'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (pg_catalog.to_jsonb(NEW) OPERATOR(pg_catalog.-) 'verified_at'::pg_catalog.text)
           IS DISTINCT FROM (pg_catalog.to_jsonb(OLD) OPERATOR(pg_catalog.-) 'verified_at'::pg_catalog.text) THEN
        RAISE EXCEPTION 'consentvault.seal is append-only: only verified_at may change'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER seal_guard BEFORE UPDATE OR DELETE ON consentvault.seal
    FOR EACH ROW EXECUTE FUNCTION consentvault.seal_guard();
CREATE TRIGGER seal_no_truncate BEFORE TRUNCATE ON consentvault.seal
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Fork guard: an insert must extend the current head, under the same advisory
-- lock the Python writer takes, so concurrent writers serialize.
CREATE FUNCTION consentvault.check_chain_head() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    head_seq  pg_catalog.int8;
    head_hash pg_catalog.text;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('consentvault.ledger'));
    SELECT seq, row_hash INTO head_seq, head_hash FROM consentvault.event ORDER BY seq DESC LIMIT 1;
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

CREATE TRIGGER event_chain_head BEFORE INSERT ON consentvault.event
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_chain_head();

-- Receipt time is the vault's own clock: a row whose received_at is not the server's current time is refused.
CREATE FUNCTION consentvault.check_received_at() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    skew pg_catalog.interval := NEW.received_at OPERATOR(pg_catalog.-) pg_catalog.clock_timestamp();
BEGIN
    IF skew OPERATOR(pg_catalog.>) '1 minute'::pg_catalog.interval
       OR skew OPERATOR(pg_catalog.<) '-1 minute'::pg_catalog.interval THEN
        RAISE EXCEPTION 'consentvault received_at: the receipt time must be the vault server''s own clock'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER event_received_check BEFORE INSERT ON consentvault.event
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_received_at();

-- Salt minting. The runtime role cannot insert into contact_salt: the only way to create a salt is this owner-defined
-- function, which draws the 32 bytes inside the database (sha256 over three random UUIDs, which the server generates
-- from its cryptographic random source) under the ledger lock, so a caller can neither choose nor predict a salt, and
-- two first events for one contact point agree on one salt.
CREATE FUNCTION consentvault.mint_contact_salt(p_contact_norm text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    held pg_catalog.bytea;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('consentvault.ledger'));
    SELECT salt INTO held FROM consentvault.contact_salt WHERE contact_norm OPERATOR(pg_catalog.=) p_contact_norm;
    IF NOT FOUND THEN
        held := pg_catalog.sha256(pg_catalog.convert_to(
            pg_catalog.gen_random_uuid()::pg_catalog.text OPERATOR(pg_catalog.||)
            pg_catalog.gen_random_uuid()::pg_catalog.text OPERATOR(pg_catalog.||)
            pg_catalog.gen_random_uuid()::pg_catalog.text, 'UTF8'));
        INSERT INTO consentvault.contact_salt (contact_norm, salt) VALUES (p_contact_norm, held);
    END IF;
    RETURN pg_catalog.encode(held, 'hex');
END;
$$;
REVOKE ALL ON FUNCTION consentvault.mint_contact_salt(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.mint_contact_salt(text) TO consentvault_app;

-- Salt guard: a row's contact_salt must be the contact's salt from consentvault.contact_salt.
CREATE FUNCTION consentvault.check_contact_salt() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    held pg_catalog.bytea;
BEGIN
    SELECT salt INTO held FROM consentvault.contact_salt WHERE contact_norm OPERATOR(pg_catalog.=) NEW.contact_norm;
    IF NOT FOUND OR pg_catalog.encode(held, 'hex') OPERATOR(pg_catalog.<>) NEW.contact_salt THEN
        RAISE EXCEPTION 'consentvault contact salt: the row must carry the contact''s own salt'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER event_contact_salt_check BEFORE INSERT ON consentvault.event
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_contact_salt();

-- Scope guard: a grant may name only channels and purposes its disclosure names.
CREATE FUNCTION consentvault.check_grant_scope() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    d_channels pg_catalog.text[];
    d_purposes pg_catalog.text[];
BEGIN
    IF NEW.event_type OPERATOR(pg_catalog.<>) 'grant' THEN
        RETURN NEW;
    END IF;
    SELECT channels, purposes INTO d_channels, d_purposes FROM consentvault.disclosure WHERE sha256 OPERATOR(pg_catalog.=) NEW.disclosure_sha256;
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

CREATE TRIGGER event_scope_check BEFORE INSERT ON consentvault.event
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_grant_scope();

-- Release guard: a release decides an earlier consumer grant of the same contact point, and names only
-- channels and purposes that grant names. A 'released' decision needs a grant whose contact point was verified.
CREATE FUNCTION consentvault.check_release_ref() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
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
    WHERE g.event_id OPERATOR(pg_catalog.=) NEW.release_of_event_id
      AND g.event_type OPERATOR(pg_catalog.=) 'grant'
      AND g.origin OPERATOR(pg_catalog.=) 'consumer'
      AND g.contact_kind OPERATOR(pg_catalog.=) NEW.contact_kind
      AND g.contact_norm OPERATOR(pg_catalog.=) NEW.contact_norm
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

CREATE TRIGGER event_release_check BEFORE INSERT ON consentvault.event
    FOR EACH ROW EXECUTE FUNCTION consentvault.check_release_ref();

-- The one permitted update for the runtime role: stamping a seal as verified.
CREATE FUNCTION consentvault.mark_seal_verified(p_seal_id bigint) RETURNS void
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    UPDATE consentvault.seal SET verified_at = pg_catalog.now() WHERE seal_id OPERATOR(pg_catalog.=) p_seal_id;
$$;
REVOKE ALL ON FUNCTION consentvault.mark_seal_verified(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.mark_seal_verified(bigint) TO consentvault_app;

-- Structural chain check in SQL (hash recomputation lives in Python).
CREATE VIEW consentvault.chain_breaks AS
SELECT seq, event_id,
       CASE WHEN expected_seq <> seq THEN 'seq_gap' ELSE 'prev_hash_mismatch' END AS reason
FROM (
    SELECT seq, event_id, prev_hash,
           coalesce(lag(seq) OVER w + 1, 1) AS expected_seq,
           coalesce(lag(row_hash) OVER w, repeat('0', 64)) AS expected_prev
    FROM consentvault.event
    WINDOW w AS (ORDER BY seq)
) t
WHERE expected_seq <> seq OR expected_prev <> prev_hash;

CREATE VIEW consentvault.unsealed_events AS
SELECT e.*
FROM consentvault.event e
WHERE NOT EXISTS (SELECT 1 FROM consentvault.seal s WHERE s.event_id = e.event_id);

-- Permission per contact point x channel x purpose. The latest event wins by seq (the order the vault
-- received them), never by a caller-supplied time. A stop outranks a grant until a later valid release.
-- A release is ranked at the position of the grant it decides, so it never lifts a stop that arrived after that grant.
-- A stop for purpose '*' stops every purpose on its channels. A stop by staff, a regulator, an import, or by a
-- method other than keyword/checkbox/written is a hard stop that nothing releases.
CREATE VIEW consentvault.current_permission AS
WITH exploded AS (
    SELECT e.contact_kind, e.contact_norm, e.event_type,
           CASE WHEN e.event_type = 'release'
                THEN (SELECT g.seq FROM consentvault.event g WHERE g.event_id = e.release_of_event_id)
                ELSE e.seq END AS rk,
           ch AS channel, pu AS purpose,
           (e.event_type IN ('revoke', 'suppress')
              AND (e.origin <> 'consumer' OR e.method NOT IN ('keyword', 'checkbox', 'written'))) AS hard_stop,
           (e.event_type = 'release' AND e.origin = 'consumer' AND e.release_outcome = 'released') AS valid_release
    FROM consentvault.event e, unnest(e.channels) AS ch, unnest(e.purposes) AS pu
),
star AS (
    SELECT contact_kind, contact_norm, channel,
           max(rk) FILTER (WHERE event_type IN ('revoke', 'suppress')) AS star_stop_rk,
           max(rk) FILTER (WHERE hard_stop)                            AS star_hard_rk
    FROM exploded
    WHERE purpose = '*'
    GROUP BY contact_kind, contact_norm, channel
),
agg AS (
    SELECT x.contact_kind, x.contact_norm, x.channel, x.purpose,
           max(x.rk) FILTER (WHERE x.event_type = 'grant')                    AS grant_rk,
           greatest(max(x.rk) FILTER (WHERE x.event_type IN ('revoke', 'suppress')), s.star_stop_rk) AS stop_rk,
           greatest(max(x.rk) FILTER (WHERE x.hard_stop), s.star_hard_rk)      AS hard_stop_rk,
           max(x.rk) FILTER (WHERE x.valid_release)                           AS release_rk
    FROM exploded x
    LEFT JOIN star s USING (contact_kind, contact_norm, channel)
    GROUP BY x.contact_kind, x.contact_norm, x.channel, x.purpose, s.star_stop_rk, s.star_hard_rk
)
SELECT a.contact_kind, a.contact_norm, a.channel, a.purpose,
       (a.grant_rk IS NOT NULL AND a.hard_stop_rk IS NULL
            AND (a.stop_rk IS NULL OR coalesce(a.release_rk > a.stop_rk, false))) AS allowed,
       CASE
           WHEN a.stop_rk IS NOT NULL
                AND (a.hard_stop_rk IS NOT NULL OR a.release_rk IS NULL OR a.release_rk < a.stop_rk)
               THEN 'stopped:' || (SELECT event_type FROM consentvault.event WHERE seq = a.stop_rk)
           WHEN a.grant_rk IS NULL THEN 'no_grant'
           ELSE 'granted'
       END AS reason,
       (SELECT event_id FROM consentvault.event
         WHERE seq = greatest(a.grant_rk, a.stop_rk, a.release_rk)) AS deciding_event_id
FROM agg a;

-- Runtime role: read everything the vault exposes, append to the ledger tables, nothing else. Salts are readable but
-- created only through consentvault.mint_contact_salt.
GRANT SELECT, INSERT ON consentvault.event, consentvault.disclosure, consentvault.seal, consentvault.chain_head,
    consentvault.contact_log, consentvault.review TO consentvault_app;
GRANT SELECT ON consentvault.contact_salt TO consentvault_app;
GRANT SELECT ON consentvault.chain_breaks, consentvault.unsealed_events, consentvault.current_permission TO consentvault_app;
GRANT USAGE ON SEQUENCE consentvault.seal_seal_id_seq, consentvault.chain_head_head_id_seq,
    consentvault.contact_log_contact_log_id_seq, consentvault.review_review_id_seq TO consentvault_app;
