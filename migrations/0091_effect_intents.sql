-- Pure projection, migration step 11's tables (specs/capture-everything/pure-projection.md, "Migration 0089": renumbered 0091; 0092 is
-- taken on another branch). Creates the effect intent table the new fold fills, the watermark table, the seed from the old queues, and the
-- replay-database test the effects layer refuses on. It RETIRES NOTHING: the old queues, ``confirmation_enqueue`` and the old sync and
-- record functions keep working until the cutover window switches them. ``seed_effect_intents`` is run by the window, not here.

CREATE TABLE consentvault.effect_intent (
    org_id      uuid NOT NULL DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    intent_id   uuid NOT NULL,            -- derived from post, effect and target (or from the legacy row); the vendor idempotency key
    post_id     uuid,
    effect      text NOT NULL,
    target      text NOT NULL,
    contact_fp  text,
    channel     text,
    state       text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'claimed', 'sent', 'unknown') OR state ~ '^failed:[a-z_]{1,40}$'),
    state_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    legacy_ref  text,
    PRIMARY KEY (org_id, intent_id),
    FOREIGN KEY (org_id, post_id) REFERENCES consentvault.raw_post (org_id, post_id),
    CONSTRAINT effect_intent_one_origin CHECK ((post_id IS NULL) <> (legacy_ref IS NULL))
);
CREATE UNIQUE INDEX effect_intent_post_key ON consentvault.effect_intent (org_id, post_id, effect, target) WHERE post_id IS NOT NULL;
CREATE UNIQUE INDEX effect_intent_legacy_key ON consentvault.effect_intent (org_id, effect, legacy_ref) WHERE legacy_ref IS NOT NULL;
CREATE INDEX effect_intent_contact_idx ON consentvault.effect_intent (org_id, contact_fp, channel, state_at);
CREATE INDEX effect_intent_state_idx ON consentvault.effect_intent (org_id, state, state_at);

-- Only the state and its time may change, and only by the definer function below (no role holds UPDATE); nothing is deleted.
CREATE FUNCTION consentvault.effect_intent_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' OR TG_OP OPERATOR(pg_catalog.=) 'TRUNCATE' THEN
        RAISE EXCEPTION 'consentvault.effect_intent: an intent is never deleted' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF (NEW.org_id, NEW.intent_id, NEW.post_id, NEW.effect, NEW.target, NEW.contact_fp, NEW.channel, NEW.legacy_ref)
       IS DISTINCT FROM (OLD.org_id, OLD.intent_id, OLD.post_id, OLD.effect, OLD.target, OLD.contact_fp, OLD.channel, OLD.legacy_ref) THEN
        RAISE EXCEPTION 'consentvault.effect_intent: only the state moves' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER effect_intent_guard BEFORE UPDATE OR DELETE ON consentvault.effect_intent
    FOR EACH ROW EXECUTE FUNCTION consentvault.effect_intent_guard();
CREATE TRIGGER effect_intent_no_truncate BEFORE TRUNCATE ON consentvault.effect_intent
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

CREATE FUNCTION consentvault.effect_intent_move(p_intent uuid, p_state text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE consentvault.effect_intent SET state = p_state, state_at = pg_catalog.clock_timestamp()
     WHERE org_id OPERATOR(pg_catalog.=) consentvault.current_org() AND intent_id OPERATOR(pg_catalog.=) p_intent;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consentvault.effect_intent: no such intent in the entered organisation' USING ERRCODE = 'no_data_found';
    END IF;
END;
$$;
REVOKE ALL ON FUNCTION consentvault.effect_intent_move(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.effect_intent_move(uuid, text) TO consentvault_app, consentvault_worker;

CREATE TABLE consentvault.effect_watermark (
    org_id   uuid PRIMARY KEY DEFAULT consentvault.current_org() REFERENCES consentvault.organization (org_id),
    head_seq bigint NOT NULL CHECK (head_seq >= 0),
    set_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER effect_watermark_append_only BEFORE UPDATE OR DELETE ON consentvault.effect_watermark
    FOR EACH ROW EXECUTE FUNCTION consentvault.refuse_change();
CREATE TRIGGER effect_watermark_no_truncate BEFORE TRUNCATE ON consentvault.effect_watermark
    FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change();

ALTER TABLE consentvault.effect_intent ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.effect_intent FORCE ROW LEVEL SECURITY;
CREATE POLICY effect_intent_tenant ON consentvault.effect_intent USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));
ALTER TABLE consentvault.effect_watermark ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentvault.effect_watermark FORCE ROW LEVEL SECURITY;
CREATE POLICY effect_watermark_tenant ON consentvault.effect_watermark USING (org_id = (SELECT consentvault.current_org()))
    WITH CHECK (org_id = (SELECT consentvault.current_org()));

GRANT SELECT ON consentvault.effect_intent, consentvault.effect_watermark TO consentvault_app, consentvault_worker, consentvault_console, consentvault_integrity;
GRANT INSERT (org_id, intent_id, post_id, effect, target, contact_fp, channel) ON consentvault.effect_intent TO consentvault_app;
GRANT INSERT (org_id, head_seq) ON consentvault.effect_watermark TO consentvault_app;

-- The intent id of a post's effect: the same on every replay, so projecting again derives the same key.
CREATE FUNCTION consentvault.effect_intent_id(p_org uuid, p_key text) RETURNS uuid
    LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.md5(p_org::pg_catalog.text OPERATOR(pg_catalog.||) '|' OPERATOR(pg_catalog.||) p_key)::pg_catalog.uuid;
$$;
GRANT EXECUTE ON FUNCTION consentvault.effect_intent_id(uuid, text) TO consentvault_app, consentvault_worker, consentvault_console;

-- True on a throwaway replay database. The effects layer and the claim refuse by name when it is.
CREATE FUNCTION consentvault.is_replay_database() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM consentvault.replay_target);
$$;
REVOKE ALL ON FUNCTION consentvault.is_replay_database() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.is_replay_database() TO consentvault_app, consentvault_worker, consentvault_console, consentvault_integrity;

-- One intent per outbox row and per confirmation row, across every organisation. Owned by the operator role (row security bypassed).
-- Outbox pending and failed -> pending; sent (claimed in flight) -> unknown; acknowledged -> sent; dead, superseded -> failed:<status>.
-- Confirmation intent -> pending; sending -> unknown; sent, delivered -> sent; failed, dead, skipped -> failed:<status>.
-- A second run adds nothing (the legacy reference is unique).
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
GRANT SELECT ON consentvault.outbox, consentvault.confirmation_send_intent TO consentvault_operator;
GRANT INSERT ON consentvault.effect_intent TO consentvault_operator;
CREATE FUNCTION consentvault.seed_effect_intents() RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_a bigint;
    v_b bigint;
BEGIN
    INSERT INTO consentvault.effect_intent (org_id, intent_id, post_id, effect, target, contact_fp, channel, state, legacy_ref)
    SELECT o.org_id, consentvault.effect_intent_id(o.org_id, 'outbox|' OPERATOR(pg_catalog.||) o.outbox_id::pg_catalog.text),
           NULL, 'push', o.system_id::pg_catalog.text, o.contact_fp, o.channel,
           CASE o.status WHEN 'pending' THEN 'pending' WHEN 'failed' THEN 'pending' WHEN 'sent' THEN 'unknown'
                         WHEN 'acknowledged' THEN 'sent' ELSE 'failed:' OPERATOR(pg_catalog.||) o.status END,
           o.outbox_id::pg_catalog.text
      FROM consentvault.outbox o
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_a = ROW_COUNT;
    INSERT INTO consentvault.effect_intent (org_id, intent_id, post_id, effect, target, contact_fp, channel, state, legacy_ref)
    SELECT c.org_id, consentvault.effect_intent_id(c.org_id, 'confirmation|' OPERATOR(pg_catalog.||) c.send_id::pg_catalog.text),
           NULL, 'confirmation', c.channel, c.contact_fp, c.channel,
           CASE c.status WHEN 'intent' THEN 'pending' WHEN 'sending' THEN 'unknown' WHEN 'sent' THEN 'sent' WHEN 'delivered' THEN 'sent'
                         ELSE 'failed:' OPERATOR(pg_catalog.||) c.status END,
           c.send_id::pg_catalog.text
      FROM consentvault.confirmation_send_intent c
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_b = ROW_COUNT;
    RETURN v_a OPERATOR(pg_catalog.+) v_b;
END;
$$;
ALTER FUNCTION consentvault.seed_effect_intents() OWNER TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.seed_effect_intents() FROM PUBLIC;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
