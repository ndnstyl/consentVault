-- Reverses 0002_tenancy.sql. Refuses while the vault holds anything a single-company schema cannot hold: multi mode,
-- a second organisation, a version-2 (encrypted) row, a contact key, or any credential, member, brand, source or key
-- record. A down migration never destroys evidence.
--
-- Run it as a superuser (or a BYPASSRLS role), in one transaction. Row security is switched off for the transaction,
-- so a role that row-level security would filter gets an error instead of counting zero rows and dropping a tenant's
-- keys; any error rolls the whole file back (with psql -1, or without it: the explicit BEGIN makes every later
-- statement fail until COMMIT, which then rolls back).
BEGIN;
SET LOCAL row_security = off;

DO $$
DECLARE
    home uuid;
    n bigint;
BEGIN
    IF to_regclass('consentvault.tenancy_setting') IS NULL THEN
        RAISE EXCEPTION 'consentvault down 0002 refused: consentvault.tenancy_setting is missing; 0002 is not applied';
    END IF;
    IF (SELECT mode FROM consentvault.tenancy_setting WHERE singleton) <> 'single' THEN
        RAISE EXCEPTION 'consentvault down 0002 refused: the vault is in multi mode';
    END IF;
    SELECT home_org_id INTO home FROM consentvault.tenancy_setting WHERE singleton;
    SELECT count(*) INTO n FROM consentvault.organization WHERE org_id <> home;
    IF n > 0 THEN
        RAISE EXCEPTION 'consentvault down 0002 refused: % organisation(s) besides the home organisation exist', n;
    END IF;
    IF EXISTS (SELECT 1 FROM consentvault.event WHERE org_id <> home OR hash_version <> 1)
       OR EXISTS (SELECT 1 FROM consentvault.contact_key)
       OR EXISTS (SELECT 1 FROM consentvault.credential)
       OR EXISTS (SELECT 1 FROM consentvault.member)
       OR EXISTS (SELECT 1 FROM consentvault.brand)
       OR EXISTS (SELECT 1 FROM consentvault.capture_source)
       OR EXISTS (SELECT 1 FROM consentvault.org_key)
       OR EXISTS (SELECT 1 FROM consentvault.contact_log WHERE contact_norm IS NULL)
       OR EXISTS (SELECT 1 FROM consentvault.review WHERE contact_norm IS NULL) THEN
        RAISE EXCEPTION 'consentvault down 0002 refused: the vault holds tenancy records (encrypted rows, keys, credentials, members, brands, sources); export them first';
    END IF;
    IF to_regclass('consentvault.replay_guard') IS NOT NULL THEN
        RAISE EXCEPTION 'consentvault down 0002 refused: run down/0003_replay_guard.sql first';
    END IF;
END
$$;

DROP VIEW consentvault.current_permission;
DROP VIEW consentvault.unsealed_events;
DROP VIEW consentvault.chain_breaks;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['event', 'contact_key', 'contact_salt', 'contact_log', 'review'] LOOP
        EXECUTE format('DROP POLICY %I ON consentvault.%I', t || '_read_scope', t);
    END LOOP;
    FOREACH t IN ARRAY ARRAY['organization', 'brand', 'capture_source', 'credential', 'member', 'org_key', 'contact_key',
                             'event', 'disclosure', 'contact_salt', 'seal', 'chain_head', 'contact_log', 'review'] LOOP
        EXECUTE format('DROP POLICY %I ON consentvault.%I', t || '_tenant', t);
        EXECUTE format('ALTER TABLE consentvault.%I NO FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I DISABLE ROW LEVEL SECURITY', t);
    END LOOP;
END
$$;

DROP TRIGGER event_clear_contact_home_only ON consentvault.event;
DROP TRIGGER contact_salt_clear_contact_home_only ON consentvault.contact_salt;
DROP TRIGGER contact_log_clear_contact_home_only ON consentvault.contact_log;
DROP TRIGGER review_clear_contact_home_only ON consentvault.review;
DROP FUNCTION consentvault.check_clear_contact_home_only();
DROP TRIGGER organization_single_mode_guard ON consentvault.organization;
DROP FUNCTION consentvault.organization_single_mode_guard();
DROP FUNCTION consentvault.may_read_evidence();
DROP FUNCTION consentvault.ledger_head();
DROP FUNCTION consentvault.contact_key_of(text);
DROP FUNCTION consentvault.mark_seal_verified(uuid);
DROP FUNCTION consentvault.require_multi_tenant();
CREATE OR REPLACE FUNCTION consentvault.mark_seal_verified(p_seal_id bigint) RETURNS void
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    UPDATE consentvault.seal SET verified_at = pg_catalog.now() WHERE seal_id OPERATOR(pg_catalog.=) p_seal_id;
$$;
DROP TRIGGER event_verified_claim ON consentvault.event;
DROP FUNCTION consentvault.check_verified_claim();

ALTER TABLE consentvault.review
    DROP CONSTRAINT review_contact_shape,
    DROP CONSTRAINT review_event_org_fkey,
    DROP COLUMN review_uuid, DROP COLUMN contact_fp, DROP COLUMN contact_ct, DROP COLUMN message_ct,
    ALTER COLUMN contact_norm SET NOT NULL;
ALTER TABLE consentvault.contact_log
    DROP CONSTRAINT contact_log_contact_shape,
    DROP COLUMN contact_log_uuid, DROP COLUMN contact_fp, DROP COLUMN contact_ct,
    ALTER COLUMN contact_norm SET NOT NULL;
ALTER TABLE consentvault.chain_head DROP COLUMN head_uuid;
ALTER TABLE consentvault.seal DROP CONSTRAINT seal_event_org_fkey, DROP COLUMN seal_uuid;

ALTER TABLE consentvault.event
    DROP CONSTRAINT event_shape_by_hash_version,
    DROP CONSTRAINT event_source_org_fkey,
    DROP CONSTRAINT event_release_of_org_fkey,
    DROP CONSTRAINT event_disclosure_org_fkey,
    DROP COLUMN contact_fp, DROP COLUMN contact_ct, DROP COLUMN subject_key_ct, DROP COLUMN subject_fp,
    DROP COLUMN subject_commit,
    DROP COLUMN evidence_sha256, DROP COLUMN key_version, DROP COLUMN source_id, DROP COLUMN brand_ids,
    DROP COLUMN page_url_ct, DROP COLUMN client_ip_ct, DROP COLUMN user_agent_ct, DROP COLUMN session_ref_ct,
    DROP COLUMN attribution_ct,
    ALTER COLUMN contact_norm SET NOT NULL,
    ALTER COLUMN contact_salt SET NOT NULL,
    ALTER COLUMN subject_key SET NOT NULL;
ALTER TABLE consentvault.event DROP CONSTRAINT event_org_event_id_key;
ALTER TABLE consentvault.event DROP CONSTRAINT event_org_row_hash_key;
ALTER TABLE consentvault.event ADD CONSTRAINT event_event_id_key UNIQUE (event_id);
ALTER TABLE consentvault.event ADD CONSTRAINT event_row_hash_key UNIQUE (row_hash);
ALTER TABLE consentvault.event DROP CONSTRAINT event_pkey;
ALTER TABLE consentvault.event ADD PRIMARY KEY (seq);
ALTER TABLE consentvault.contact_salt DROP CONSTRAINT contact_salt_pkey;
ALTER TABLE consentvault.contact_salt ADD PRIMARY KEY (contact_norm);
ALTER TABLE consentvault.disclosure DROP CONSTRAINT disclosure_pkey;
ALTER TABLE consentvault.disclosure ADD PRIMARY KEY (sha256);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['event', 'disclosure', 'contact_salt', 'seal', 'chain_head', 'contact_log', 'review'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I DROP COLUMN org_id', t);
    END LOOP;
END
$$;

-- The 0001 foreign keys and functions, as they were.
ALTER TABLE consentvault.event
    ADD CONSTRAINT event_disclosure_sha256_fkey FOREIGN KEY (disclosure_sha256) REFERENCES consentvault.disclosure (sha256),
    ADD CONSTRAINT event_release_of_event_id_fkey FOREIGN KEY (release_of_event_id) REFERENCES consentvault.event (event_id);
ALTER TABLE consentvault.seal ADD CONSTRAINT seal_event_id_fkey FOREIGN KEY (event_id) REFERENCES consentvault.event (event_id);
ALTER TABLE consentvault.review ADD CONSTRAINT review_event_id_fkey FOREIGN KEY (event_id) REFERENCES consentvault.event (event_id);

CREATE OR REPLACE FUNCTION consentvault.check_chain_head() RETURNS trigger LANGUAGE plpgsql
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

CREATE OR REPLACE FUNCTION consentvault.mint_contact_salt(p_contact_norm text) RETURNS text
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

CREATE OR REPLACE FUNCTION consentvault.check_contact_salt() RETURNS trigger LANGUAGE plpgsql
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

CREATE OR REPLACE FUNCTION consentvault.check_grant_scope() RETURNS trigger LANGUAGE plpgsql
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

CREATE OR REPLACE FUNCTION consentvault.check_release_ref() RETURNS trigger LANGUAGE plpgsql
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

-- The 0001 views, as they were.
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

GRANT SELECT ON consentvault.chain_breaks, consentvault.unsealed_events, consentvault.current_permission TO consentvault_app;

-- The views were recreated by whoever runs this file (a superuser); hand them back to the schema owner.
DO $$
DECLARE
    owner_name text := (SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'consentvault.event'::regclass);
    v text;
BEGIN
    FOREACH v IN ARRAY ARRAY['chain_breaks', 'unsealed_events', 'current_permission'] LOOP
        EXECUTE format('ALTER VIEW consentvault.%I OWNER TO %I', v, owner_name);
    END LOOP;
END
$$;

DROP FUNCTION consentvault.dispatch_orgs(text);
DROP FUNCTION consentvault.active_org_ids();
DROP FUNCTION consentvault.resolve_member(text, text);
DROP FUNCTION consentvault.resolve_credential(uuid);
DROP FUNCTION consentvault.ledger_lock_key(uuid);
DROP FUNCTION consentvault.enable_multi_tenant();
DROP FUNCTION consentvault.retire_token_key(text);
DROP FUNCTION consentvault.install_token_key(text, bytea);
DROP FUNCTION consentvault.sign_org_token(uuid, text[], text, integer);
DROP FUNCTION consentvault.enter_org(text);
DROP FUNCTION consentvault.current_token_scopes();

-- Columns defaulting to current_org() are gone; now the tables and functions that remain.
DROP TABLE consentvault.contact_key;
DROP TABLE consentvault.org_key;
DROP TABLE consentvault.member;
DROP TABLE consentvault.credential;
DROP TABLE consentvault.capture_source;
DROP TABLE consentvault.brand;
DROP TABLE consentvault.tenant_token_key;
DROP TABLE consentvault.tenancy_setting;
DROP FUNCTION consentvault.tenancy_setting_guard();
DROP TABLE consentvault.organization;
DROP FUNCTION consentvault.current_org();
DROP FUNCTION consentvault.verify_org_token(text);
DROP FUNCTION consentvault.home_org();
DROP FUNCTION consentvault.hmac_sha256(bytea, bytea);
DROP FUNCTION consentvault.random_internal_id();

REVOKE USAGE ON SCHEMA consentvault FROM consentvault_operator, consentvault_worker;
-- The group roles consentvault_operator and consentvault_worker are cluster-wide and are left in place.
COMMIT;
