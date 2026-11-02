-- The contact record list (records.md sections 1, 2, 8 and 9): one record per contact point per organisation, the derived
-- index the list reads, the display table that holds a person's name and company, and the display key that seals them.
--
-- * record: never rebuilt and never deleted. record_id is a random uuid minted when a contact point is first recorded
--   (not derived from the contact), so it may sit in a URL and it survives erasure. A fingerprint has at most one ACTIVE
--   record (erased_at is null); after an erasure a later capture of the same contact point mints a new record.
--   first_seq is the ledger sequence of the record's first event: the events of a record are those from first_seq up to
--   the next record of the same fingerprint, so nothing of an erased record is carried into the new one.
-- * record_index: derived from the ledger, rebuildable (record_index_rebuild), not evidence. Never holds a contact point
--   in clear; mask_ct is the masked contact sealed under the display key.
-- * record_display: name and company sealed under the display key, bound to organisation, record and column. Mutable,
--   not evidence, never hashed into the chain. Deleted outright by an erasure. Readable only by an admin or a viewer.
-- * org_display_key: one random 256-bit secret per organisation, wrapped by the organisation key exactly as the
--   fingerprint secret is. It changes only by a re-wrap under a newer organisation key version (key rotation).
--
-- Every writer is an owner-rights function that takes the organisation from the token and its scopes
-- (consentvault.sync_org), checks the event belongs to that organisation and fingerprint, and takes the ledger lock.
-- consentvault.erase_contact(text) is redefined to also delete the display row, null the mask and mark the record erased,
-- in the same transaction as the key delete. The key version census and the re-wrap function learn the display key.

-- The phone region an organization's national-format numbers are read with (records.md section 5). Set by the operator.
ALTER TABLE consentvault.organization
    ADD COLUMN default_region text NOT NULL DEFAULT 'US' CHECK (default_region ~ '^[A-Z]{2}$');

CREATE TABLE consentvault.record (
    org_id            uuid NOT NULL REFERENCES consentvault.organization (org_id),
    record_id         uuid NOT NULL DEFAULT gen_random_uuid(),
    contact_fp        text NOT NULL CHECK (contact_fp ~ '^[0-9a-f]{64}$'),
    contact_kind      text NOT NULL CHECK (contact_kind IN ('phone', 'email')),
    first_recorded_at timestamptz NOT NULL,
    first_seq         bigint NOT NULL DEFAULT 1 CHECK (first_seq >= 1),
    erased_at         timestamptz,
    PRIMARY KEY (org_id, record_id)
);
CREATE UNIQUE INDEX record_one_active_idx ON consentvault.record (org_id, contact_fp) WHERE erased_at IS NULL;
CREATE INDEX record_fp_idx ON consentvault.record (org_id, contact_fp, first_seq);

CREATE TABLE consentvault.record_index (
    org_id          uuid NOT NULL,
    record_id       uuid NOT NULL,
    subject_fp      text CHECK (subject_fp IS NULL OR subject_fp ~ '^[0-9a-f]{64}$'),
    last_event_at   timestamptz NOT NULL,
    first_source_id uuid,
    source_ids      uuid[] NOT NULL DEFAULT '{}',
    brand_ids       uuid[] NOT NULL DEFAULT '{}',
    status_by_cell  jsonb NOT NULL DEFAULT '{}'::jsonb,
    has_stop        boolean NOT NULL DEFAULT false,
    last_stop_at    timestamptz,
    first_in_trial  boolean NOT NULL DEFAULT false,
    last_confirmation jsonb,
    mask_ct         bytea,
    PRIMARY KEY (org_id, record_id),
    FOREIGN KEY (org_id, record_id) REFERENCES consentvault.record (org_id, record_id)
);
CREATE INDEX record_index_last_event_idx ON consentvault.record_index (org_id, last_event_at DESC, record_id DESC);
CREATE INDEX record_index_subject_idx ON consentvault.record_index (org_id, subject_fp) WHERE subject_fp IS NOT NULL;

CREATE TABLE consentvault.record_display (
    org_id     uuid NOT NULL,
    record_id  uuid NOT NULL,
    name_ct    bytea,
    company_ct bytea,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (org_id, record_id),
    FOREIGN KEY (org_id, record_id) REFERENCES consentvault.record (org_id, record_id),
    CONSTRAINT record_display_one_field CHECK (name_ct IS NOT NULL OR company_ct IS NOT NULL)
);

CREATE TABLE consentvault.org_display_key (
    org_id      uuid PRIMARY KEY REFERENCES consentvault.organization (org_id),
    wrapped     bytea NOT NULL CHECK (octet_length(wrapped) > 0),
    key_version integer NOT NULL CHECK (key_version >= 1),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- A record is never deleted; the only change it takes is the day it is erased. -------------------------------------------------
CREATE FUNCTION consentvault.record_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' THEN
        RAISE EXCEPTION 'consentvault.record is never deleted: DELETE refused' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.erased_at IS NOT NULL
       OR NEW.erased_at IS NULL
       OR (NEW.org_id, NEW.record_id, NEW.contact_fp, NEW.contact_kind, NEW.first_recorded_at, NEW.first_seq)
          IS DISTINCT FROM (OLD.org_id, OLD.record_id, OLD.contact_fp, OLD.contact_kind, OLD.first_recorded_at, OLD.first_seq) THEN
        RAISE EXCEPTION 'consentvault.record changes only when it is erased (erased_at from null to a time): UPDATE refused'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER record_guard BEFORE UPDATE OR DELETE ON consentvault.record
    FOR EACH ROW EXECUTE FUNCTION consentvault.record_guard();
CREATE TRIGGER record_no_truncate BEFORE TRUNCATE ON consentvault.record
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- The display key row changes only by a re-wrap under a newer key version, as the fingerprint secret does. ------------------
CREATE FUNCTION consentvault.org_display_key_guard() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' OR NOT consentvault.rewrap_allowed(TG_RELID)
       OR (NEW.org_id, NEW.created_at) IS DISTINCT FROM (OLD.org_id, OLD.created_at)
       OR consentvault.wrap_version(NEW.wrapped) <= consentvault.wrap_version(OLD.wrapped)
       OR NEW.key_version IS DISTINCT FROM consentvault.wrap_version(NEW.wrapped) THEN
        RAISE EXCEPTION 'consentvault.org_display_key is append-only: % refused (only a re-wrap under a newer key version changes it)',
            TG_OP USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER org_display_key_append_only BEFORE UPDATE OR DELETE ON consentvault.org_display_key
    FOR EACH ROW EXECUTE FUNCTION consentvault.org_display_key_guard();
CREATE TRIGGER org_display_key_no_truncate BEFORE TRUNCATE ON consentvault.org_display_key
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

-- Row security: by organisation like every tenant table, and a restrictive read scope on the two tables that hold names --------
-- and the wrapped key (the pattern of may_read_evidence): an owner-rights function reads them; a session reads names only
-- under an admin or proof_read token, and the wrapped display key only under the display-key loader's own scope.
CREATE FUNCTION consentvault.may_read_names() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.record_display'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'proof_read', 'records_read'], false);
$$;
REVOKE ALL ON FUNCTION consentvault.may_read_names() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.may_read_names() TO consentvault_app, consentvault_worker, consentvault_console;

-- The record list and its index are read by an admin, a developer (fingerprints only) and a viewer; never by a capture token.
CREATE FUNCTION consentvault.may_read_records() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.record'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['admin', 'developer', 'proof_read', 'records_read'], false);
$$;
REVOKE ALL ON FUNCTION consentvault.may_read_records() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.may_read_records() TO consentvault_app, consentvault_worker, consentvault_console;

CREATE FUNCTION consentvault.may_read_display_key() RETURNS boolean
    LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT current_user = (SELECT pg_get_userbyid(c.relowner) FROM pg_class c WHERE c.oid = 'consentvault.org_display_key'::regclass)
        OR coalesce(consentvault.current_token_scopes() && ARRAY['worker:display_key'], false);
$$;
REVOKE ALL ON FUNCTION consentvault.may_read_display_key() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.may_read_display_key() TO consentvault_app, consentvault_worker, consentvault_console;

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['record', 'record_index', 'record_display', 'org_display_key'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
        EXECUTE format('REVOKE ALL ON consentvault.%I FROM PUBLIC', t);
    END LOOP;
    CREATE POLICY record_read_scope ON consentvault.record AS RESTRICTIVE FOR SELECT
        USING ((SELECT consentvault.may_read_records()));
    CREATE POLICY record_index_read_scope ON consentvault.record_index AS RESTRICTIVE FOR SELECT
        USING ((SELECT consentvault.may_read_records()));
    CREATE POLICY record_display_read_scope ON consentvault.record_display AS RESTRICTIVE FOR SELECT
        USING ((SELECT consentvault.may_read_names()));
    CREATE POLICY org_display_key_read_scope ON consentvault.org_display_key AS RESTRICTIVE FOR SELECT
        USING ((SELECT consentvault.may_read_display_key()));
END
$$;

-- The list reads these under the portal's own session; nothing here is written by a session, only by the functions below.
GRANT SELECT ON consentvault.record, consentvault.record_index, consentvault.record_display, consentvault.org_display_key
    TO consentvault_app;
-- The operator console makes the display key when it makes the organisation, and reads it for the key-version census.
GRANT SELECT, INSERT ON consentvault.org_display_key TO consentvault_console;
-- The backfill (records_backfill.py) reads which contact points already have a record.
GRANT SELECT ON consentvault.record TO consentvault_console;

-- Internal: recompute the derived columns of one record from the ledger. Called only by the definer functions below. -------
CREATE FUNCTION consentvault.record_index_derive(p_org uuid, p_record_id uuid, p_mask_ct bytea) RETURNS void
    LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r        record;
    nxt      bigint;
    cell_json jsonb;
    stopped  boolean;
    stop_at  timestamptz;
    last_at  timestamptz;
    subj     text;
    first_src uuid;
    srcs     uuid[];
    brs      uuid[];
    trial    boolean;
BEGIN
    SELECT rc.* INTO r FROM consentvault.record rc WHERE rc.org_id = p_org AND rc.record_id = p_record_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: record % is not in the current organisation', p_record_id
            USING ERRCODE = 'no_data_found';
    END IF;
    SELECT min(n.first_seq) INTO nxt FROM consentvault.record n
     WHERE n.org_id = p_org AND n.contact_fp = r.contact_fp AND n.first_seq > r.first_seq;

    WITH cp AS (
        SELECT c.channel, c.purpose, c.allowed, c.reason
          FROM consentvault.current_permission c WHERE c.org_id = p_org AND c.contact_fp = r.contact_fp
    ), cells AS (
        SELECT ch.channel, pu.purpose,
               CASE WHEN own.channel IS NOT NULL THEN
                        CASE WHEN own.allowed THEN 'consent_record_found'
                             WHEN left(own.reason, 8) = 'stopped:' THEN 'stop_on_record'
                             ELSE 'no_record' END
                    WHEN star.channel IS NOT NULL AND left(star.reason, 8) = 'stopped:' THEN 'stop_on_record'
                    ELSE 'no_record' END AS status
          FROM consentvault.channel ch
          LEFT JOIN consentvault.purpose pu ON pu.org_id = ch.org_id
          LEFT JOIN cp own ON own.channel = ch.channel AND own.purpose = pu.purpose
          LEFT JOIN cp star ON star.channel = ch.channel AND star.purpose = '*'
         WHERE ch.org_id = p_org
    )
    SELECT coalesce(jsonb_object_agg(x.channel, x.by_purpose), '{}'::jsonb),
           coalesce(bool_or(x.any_stop), false)
      INTO cell_json, stopped
      FROM (SELECT channel,
                   coalesce(jsonb_object_agg(purpose, status) FILTER (WHERE purpose IS NOT NULL), '{}'::jsonb) AS by_purpose,
                   coalesce(bool_or(status = 'stop_on_record') FILTER (WHERE purpose IS NOT NULL), false) AS any_stop
              FROM cells GROUP BY channel) x;

    SELECT max(e.received_at) FILTER (WHERE e.event_type IN ('revoke', 'suppress')), max(e.received_at)
      INTO stop_at, last_at
      FROM consentvault.event e
     WHERE e.org_id = p_org AND e.contact_fp = r.contact_fp AND e.seq >= r.first_seq AND (nxt IS NULL OR e.seq < nxt);
    SELECT e.subject_fp INTO subj FROM consentvault.event e
     WHERE e.org_id = p_org AND e.contact_fp = r.contact_fp AND e.seq >= r.first_seq AND (nxt IS NULL OR e.seq < nxt)
     ORDER BY e.seq DESC LIMIT 1;
    SELECT s.source_id INTO first_src FROM consentvault.event s
     WHERE s.org_id = p_org AND s.contact_fp = r.contact_fp AND s.seq >= r.first_seq AND (nxt IS NULL OR s.seq < nxt)
       AND s.source_id IS NOT NULL ORDER BY s.seq LIMIT 1;
    SELECT coalesce(array_agg(g.source_id ORDER BY g.first_seq), '{}') INTO srcs
      FROM (SELECT s.source_id, min(s.seq) AS first_seq FROM consentvault.event s
             WHERE s.org_id = p_org AND s.contact_fp = r.contact_fp AND s.seq >= r.first_seq AND (nxt IS NULL OR s.seq < nxt)
               AND s.source_id IS NOT NULL GROUP BY s.source_id) g;
    SELECT coalesce(array_agg(DISTINCT b ORDER BY b), '{}') INTO brs
      FROM consentvault.event e, unnest(e.brand_ids) AS b
     WHERE e.org_id = p_org AND e.contact_fp = r.contact_fp AND e.seq >= r.first_seq AND (nxt IS NULL OR e.seq < nxt);
    SELECT o.status = 'trial' INTO trial FROM consentvault.organization o WHERE o.org_id = p_org;

    INSERT INTO consentvault.record_index (org_id, record_id, subject_fp, last_event_at, first_source_id, source_ids, brand_ids,
                                           status_by_cell, has_stop, last_stop_at, first_in_trial, mask_ct)
    VALUES (p_org, p_record_id, subj, coalesce(last_at, r.first_recorded_at), first_src, srcs, brs, cell_json, stopped, stop_at,
            coalesce(trial, false), CASE WHEN r.erased_at IS NULL THEN p_mask_ct END)
    ON CONFLICT (org_id, record_id) DO UPDATE
       SET subject_fp = EXCLUDED.subject_fp, last_event_at = EXCLUDED.last_event_at,
           first_source_id = EXCLUDED.first_source_id, source_ids = EXCLUDED.source_ids, brand_ids = EXCLUDED.brand_ids,
           status_by_cell = EXCLUDED.status_by_cell, has_stop = EXCLUDED.has_stop, last_stop_at = EXCLUDED.last_stop_at,
           mask_ct = CASE WHEN r.erased_at IS NULL THEN coalesce(consentvault.record_index.mask_ct, EXCLUDED.mask_ct)
                          ELSE NULL END;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_index_derive(uuid, uuid, bytea) FROM PUBLIC;

-- The active record of a fingerprint, made when there is none. -------------------------------------------------------------
CREATE FUNCTION consentvault.record_upsert(p_event_id uuid, p_contact_fp text, p_contact_kind text) RETURNS uuid
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
    ev  record;
    rid uuid;
BEGIN
    SELECT e.contact_fp AS fp, e.contact_kind AS kind, e.seq AS sq, e.received_at AS rcv
      INTO ev FROM consentvault.event e WHERE e.org_id = org AND e.event_id = p_event_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: event % is not in the current organisation', p_event_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF ev.fp IS DISTINCT FROM p_contact_fp OR ev.kind IS DISTINCT FROM p_contact_kind THEN
        RAISE EXCEPTION 'consentvault records: event % is not for that contact fingerprint and kind', p_event_id
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(consentvault.ledger_lock_key(org));
    SELECT r.record_id INTO rid FROM consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND r.erased_at IS NULL;
    IF NOT FOUND THEN
        INSERT INTO consentvault.record (org_id, contact_fp, contact_kind, first_recorded_at, first_seq)
        VALUES (org, p_contact_fp, p_contact_kind, ev.rcv, ev.sq) RETURNING record_id INTO rid;
    END IF;
    RETURN rid;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_upsert(uuid, text, text) FROM PUBLIC;

-- The derived index of the active record, from every current_permission row of the fingerprint. -----------------------------
CREATE FUNCTION consentvault.record_index_refresh(p_event_id uuid, p_contact_fp text, p_mask_ct bytea) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
    ev  record;
    rid uuid;
BEGIN
    SELECT e.contact_fp AS fp INTO ev FROM consentvault.event e WHERE e.org_id = org AND e.event_id = p_event_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: event % is not in the current organisation', p_event_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF ev.fp IS DISTINCT FROM p_contact_fp THEN
        RAISE EXCEPTION 'consentvault records: event % is not for that contact fingerprint', p_event_id
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(consentvault.ledger_lock_key(org));
    SELECT r.record_id INTO rid FROM consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND r.erased_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: no active record for that fingerprint; record_upsert comes first'
            USING ERRCODE = 'no_data_found';
    END IF;
    PERFORM consentvault.record_index_derive(org, rid, p_mask_ct);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_index_refresh(uuid, text, bytea) FROM PUBLIC;

-- The name and company of a record, sealed by the caller under the display key; replaces the row. --------------------------------
CREATE FUNCTION consentvault.record_display_write(p_record_id uuid, p_name_ct bytea, p_company_ct bytea) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin']);
BEGIN
    IF p_name_ct IS NULL AND p_company_ct IS NULL THEN
        RAISE EXCEPTION 'consentvault records: a display row needs a name or a company' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(consentvault.ledger_lock_key(org));
    PERFORM 1 FROM consentvault.record r WHERE r.org_id = org AND r.record_id = p_record_id AND r.erased_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: record % is not an active record of the current organisation', p_record_id
            USING ERRCODE = 'no_data_found';
    END IF;
    INSERT INTO consentvault.record_display (org_id, record_id, name_ct, company_ct, updated_at)
    VALUES (org, p_record_id, p_name_ct, p_company_ct, clock_timestamp())
    ON CONFLICT (org_id, record_id) DO UPDATE
       SET name_ct = EXCLUDED.name_ct, company_ct = EXCLUDED.company_ct, updated_at = EXCLUDED.updated_at;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_display_write(uuid, bytea, bytea) FROM PUBLIC;

-- The confirmation sender's writer: the latest fact wins (a later send replaces an earlier skip or failure). -------------------
CREATE FUNCTION consentvault.record_index_set_confirmation(p_record_id uuid, p_channel text, p_status text, p_at timestamptz)
    RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['capture', 'capture_verified', 'admin', 'worker:confirmations']);
    cur timestamptz;
BEGIN
    IF p_status IS NULL OR p_status NOT IN ('sent', 'delivered', 'failed', 'dead', 'skipped') THEN
        RAISE EXCEPTION 'consentvault records: a confirmation status is sent, delivered, failed, dead or skipped'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_channel IS NULL OR p_channel !~ '^[a-z][a-z_]{0,31}$' OR p_at IS NULL THEN
        RAISE EXCEPTION 'consentvault records: a confirmation names its channel and the time of the fact'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT (i.last_confirmation ->> 'at')::timestamptz INTO cur FROM consentvault.record_index i
     WHERE i.org_id = org AND i.record_id = p_record_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: record % has no index row in the current organisation', p_record_id
            USING ERRCODE = 'no_data_found';
    END IF;
    IF cur IS NOT NULL AND cur > p_at THEN
        RETURN;
    END IF;
    UPDATE consentvault.record_index i
       SET last_confirmation = jsonb_build_object('last_status', p_status, 'channel', p_channel,
                                                  'at', to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
     WHERE i.org_id = org AND i.record_id = p_record_id;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_index_set_confirmation(uuid, text, text, timestamptz) FROM PUBLIC;

-- Operator and admin: recompute the derived columns of one record from the ledger. Never touches record or record_display. -----
CREATE FUNCTION consentvault.record_index_rebuild(p_record_id uuid) RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin']);
BEGIN
    PERFORM pg_advisory_xact_lock(consentvault.ledger_lock_key(org));
    PERFORM 1 FROM consentvault.record r WHERE r.org_id = org AND r.record_id = p_record_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault records: record % is not in the current organisation', p_record_id
            USING ERRCODE = 'no_data_found';
    END IF;
    PERFORM consentvault.record_index_derive(org, p_record_id, NULL);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_index_rebuild(uuid) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION consentvault.record_upsert(uuid, text, text), consentvault.record_index_refresh(uuid, text, bytea),
    consentvault.record_display_write(uuid, bytea, bytea) TO consentvault_app, consentvault_console;
GRANT EXECUTE ON FUNCTION consentvault.record_index_set_confirmation(uuid, text, text, timestamptz)
    TO consentvault_app, consentvault_worker, consentvault_console;
GRANT EXECUTE ON FUNCTION consentvault.record_index_rebuild(uuid) TO consentvault_app, consentvault_console;

-- Erasure: the display row is deleted outright, the mask is nulled and the record is marked erased, in the transaction ---------
-- that deletes the contact key. The record keeps its row. (Body of 0014 plus the three statements after the key delete.)
CREATE OR REPLACE FUNCTION consentvault.erase_contact(p_contact_fp text) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.lifecycle_lock();
    h   uuid;
    n   integer;
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
    DELETE FROM consentvault.record_display d
     USING consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND d.org_id = r.org_id AND d.record_id = r.record_id;
    UPDATE consentvault.record_index i SET mask_ct = NULL
      FROM consentvault.record r
     WHERE r.org_id = org AND r.contact_fp = p_contact_fp AND i.org_id = r.org_id AND i.record_id = r.record_id
       AND i.mask_ct IS NOT NULL;
    UPDATE consentvault.record SET erased_at = clock_timestamp()
     WHERE org_id = org AND contact_fp = p_contact_fp AND erased_at IS NULL;
    RETURN n > 0;
END;
$$;

-- Key rotation: the display key is wrapped by the organisation key, so the census counts it and the re-wrap moves it. ----------
CREATE OR REPLACE FUNCTION consentvault.key_version_census_of(p_org uuid, p_version integer) RETURNS TABLE (kind text, n bigint)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT 'contact_key', count(*) FROM consentvault.contact_key WHERE org_id = p_org AND key_version = p_version
    UNION ALL
    SELECT 'fingerprint_secret', count(*) FROM consentvault.org_fingerprint_secret
     WHERE org_id = p_org AND consentvault.wrap_version(wrapped) = p_version
    UNION ALL
    SELECT 'display_key', count(*) FROM consentvault.org_display_key
     WHERE org_id = p_org AND consentvault.wrap_version(wrapped) = p_version
    UNION ALL
    SELECT 'credential', count(*) FROM consentvault.credential
     WHERE org_id = p_org AND secret_ct IS NOT NULL AND consentvault.wrap_version(secret_ct) = p_version
    UNION ALL
    SELECT 'connected_system', count(*) FROM consentvault.connected_system
     WHERE org_id = p_org AND credentials_ct IS NOT NULL AND consentvault.wrap_version(credentials_ct) = p_version
    UNION ALL
    SELECT 'final_export', count(*) FROM consentvault.offboarding_request
     WHERE org_id = p_org AND final_export_wrapped IS NOT NULL AND consentvault.wrap_version(final_export_wrapped) = p_version
    UNION ALL
    SELECT 'hold_reason', count(*) FROM consentvault.legal_hold
     WHERE org_id = p_org AND (consentvault.sealed_version(reason) = p_version
                               OR consentvault.sealed_version(release_reason) = p_version);
$$;

CREATE OR REPLACE FUNCTION consentvault.rewrap_org_secret(p_kind text, p_ref uuid, p_old bytea, p_new bytea) RETURNS boolean
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    org uuid := consentvault.current_org();
    n   integer;
BEGIN
    PERFORM consentvault.rewrap_target_ok(org, consentvault.wrap_version(p_new));
    IF p_old IS NULL OR consentvault.wrap_version(p_new) <= consentvault.wrap_version(p_old) THEN
        RAISE EXCEPTION 'consentvault re-wrap refused: a secret moves to a newer key version'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM set_config('consentvault.rewrap', 'on', true);
    IF p_kind = 'fingerprint_secret' THEN
        UPDATE consentvault.org_fingerprint_secret SET wrapped = p_new WHERE org_id = org AND wrapped = p_old;
    ELSIF p_kind = 'display_key' THEN
        UPDATE consentvault.org_display_key SET wrapped = p_new, key_version = consentvault.wrap_version(p_new)
         WHERE org_id = org AND wrapped = p_old;
    ELSIF p_kind = 'credential' THEN
        UPDATE consentvault.credential SET secret_ct = p_new
         WHERE org_id = org AND credential_id = p_ref AND secret_ct = p_old;
    ELSIF p_kind = 'connected_system' THEN
        UPDATE consentvault.connected_system SET credentials_ct = p_new
         WHERE org_id = org AND system_id = p_ref AND credentials_ct = p_old;
    ELSE
        PERFORM set_config('consentvault.rewrap', 'off', true);
        RAISE EXCEPTION 'consentvault re-wrap refused: unknown secret kind %', p_kind USING ERRCODE = 'invalid_parameter_value';
    END IF;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('consentvault.rewrap', 'off', true);
    RETURN n = 1;
END;
$$;

-- Search and reveal share one call counter per member and window, kept here so every process sees the same count, and a --------
-- log of the records revealed so the volume alarm counts distinct records (records.md sections 5 and 6). Both tables are
-- reached only through the two functions below.
CREATE TABLE consentvault.record_call (
    org_id    uuid NOT NULL REFERENCES consentvault.organization (org_id),
    member_id text NOT NULL CHECK (length(member_id) BETWEEN 1 AND 200),
    at        timestamptz NOT NULL
);
CREATE INDEX record_call_member_idx ON consentvault.record_call (org_id, member_id, at);
CREATE TABLE consentvault.record_reveal_log (
    org_id    uuid NOT NULL REFERENCES consentvault.organization (org_id),
    member_id text NOT NULL CHECK (length(member_id) BETWEEN 1 AND 200),
    record_id uuid NOT NULL,
    at        timestamptz NOT NULL
);
CREATE INDEX record_reveal_log_org_idx ON consentvault.record_reveal_log (org_id, at);
CREATE INDEX record_reveal_log_member_idx ON consentvault.record_reveal_log (org_id, member_id, at);
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['record_call', 'record_reveal_log'] LOOP
        EXECUTE format('ALTER TABLE consentvault.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE consentvault.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY %I ON consentvault.%I USING (org_id = (SELECT consentvault.current_org()))'
                       ' WITH CHECK (org_id = (SELECT consentvault.current_org()))', t || '_tenant', t);
        EXECUTE format('REVOKE ALL ON consentvault.%I FROM PUBLIC', t);
    END LOOP;
END
$$;

-- Take one call from the member's window: answers 0 when allowed (and counts it), else the seconds until the oldest call in
-- the window ages out. The member's lock makes the count and the insert one step, whichever process asks.
CREATE FUNCTION consentvault.record_call_take(p_member text, p_now timestamptz, p_limit integer, p_window_seconds integer)
    RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org    uuid := consentvault.sync_org(ARRAY['admin', 'proof_read']);
    win    interval := make_interval(secs => p_window_seconds);
    n      integer;
    oldest timestamptz;
BEGIN
    IF p_member IS NULL OR p_limit < 1 OR p_window_seconds < 1 THEN
        RAISE EXCEPTION 'consentvault records: a call limit needs a member, a limit and a window' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('consentvault.record_call:' || org::text || ':' || p_member));
    DELETE FROM consentvault.record_call c WHERE c.org_id = org AND c.member_id = p_member AND c.at <= p_now - win;
    SELECT count(*), min(c.at) INTO n, oldest FROM consentvault.record_call c
     WHERE c.org_id = org AND c.member_id = p_member AND c.at > p_now - win;
    IF n >= p_limit THEN
        RETURN greatest(1, ceil(extract(epoch FROM (oldest + win - p_now)))::integer);
    END IF;
    INSERT INTO consentvault.record_call (org_id, member_id, at) VALUES (org, p_member, p_now);
    RETURN 0;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_call_take(text, timestamptz, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.record_call_take(text, timestamptz, integer, integer) TO consentvault_app, consentvault_console;

-- Note the records one member revealed and open the volume alarm when a line is passed: more than 1,000 distinct records by
-- one member in 60 minutes, or more than 5,000 by the organization in 24 hours. At most one alarm is open per member and one
-- for the organization. An alarm row only; nothing is sent. Answers the alarms this call opened.
CREATE FUNCTION consentvault.record_reveal_note(p_member text, p_record_ids uuid[], p_now timestamptz)
    RETURNS TABLE (alarm_member text, alarm_count bigint, alarm_window text)
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    org uuid := consentvault.sync_org(ARRAY['admin', 'proof_read']);
    m   bigint;
    o   bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('consentvault.reveal_note:' || org::text));
    IF (SELECT count(*) FROM consentvault.record r WHERE r.org_id = org AND r.record_id = ANY (p_record_ids))
       <> (SELECT count(DISTINCT x) FROM unnest(p_record_ids) x) THEN
        RAISE EXCEPTION 'consentvault records: a revealed record is not in the current organisation' USING ERRCODE = 'no_data_found';
    END IF;
    INSERT INTO consentvault.record_reveal_log (org_id, member_id, record_id, at)
    SELECT org, p_member, x, p_now FROM unnest(p_record_ids) x;
    DELETE FROM consentvault.record_reveal_log l WHERE l.org_id = org AND l.at <= p_now - interval '24 hours';
    SELECT count(DISTINCT l.record_id) INTO m FROM consentvault.record_reveal_log l
     WHERE l.org_id = org AND l.member_id = p_member AND l.at > p_now - interval '60 minutes';
    SELECT count(DISTINCT l.record_id) INTO o FROM consentvault.record_reveal_log l
     WHERE l.org_id = org AND l.at > p_now - interval '24 hours';
    IF m > 1000 AND NOT EXISTS (SELECT 1 FROM consentvault.org_alarm a WHERE a.org_id = org AND a.kind = 'reveal_volume'
                                   AND a.cleared_at IS NULL AND a.detail ->> 'member_id' = p_member) THEN
        INSERT INTO consentvault.org_alarm (org_id, kind, detail)
        VALUES (org, 'reveal_volume', jsonb_build_object('member_id', p_member, 'count', m, 'window', '60m'));
        alarm_member := p_member; alarm_count := m; alarm_window := '60m';
        RETURN NEXT;
    END IF;
    IF o > 5000 AND NOT EXISTS (SELECT 1 FROM consentvault.org_alarm a WHERE a.org_id = org AND a.kind = 'reveal_volume'
                                   AND a.cleared_at IS NULL AND a.detail ->> 'member_id' IS NULL) THEN
        INSERT INTO consentvault.org_alarm (org_id, kind, detail)
        VALUES (org, 'reveal_volume', jsonb_build_object('member_id', NULL, 'count', o, 'window', '24h'));
        alarm_member := NULL; alarm_count := o; alarm_window := '24h';
        RETURN NEXT;
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.record_reveal_note(text, uuid[], timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.record_reveal_note(text, uuid[], timestamptz) TO consentvault_app, consentvault_console;
