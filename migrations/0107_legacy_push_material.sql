-- Pure projection, cutover window: what the effects layer needs to send a push that was queued in the outbox before the cutover and seeded as
-- an effect intent (its legacy reference is the outbox id), and the answer the old outbox worker asks before it runs: has any organisation cut
-- over. Both are definers owned by the operator role (row security bypassed); the first is read in the entered organisation only.
CREATE FUNCTION consentvault.effect_legacy_push_material(p_intent uuid)
    RETURNS TABLE (outbox_id uuid, system_id uuid, endpoint text, signature text, credentials_ct bytea, system_status text, contact_fp text,
                   channel text, purpose text, version integer, payload_ct bytea, wrapped_key bytea, key_version integer)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT o.outbox_id, s.system_id, s.endpoint, s.signature, s.credentials_ct, s.status, o.contact_fp, o.channel, o.purpose, o.version,
           o.payload_ct, k.wrapped_key, k.key_version
      FROM consentvault.effect_intent i
      JOIN consentvault.outbox o ON o.org_id OPERATOR(pg_catalog.=) i.org_id AND o.outbox_id::pg_catalog.text OPERATOR(pg_catalog.=) i.legacy_ref
      JOIN consentvault.connected_system s ON s.org_id OPERATOR(pg_catalog.=) o.org_id AND s.system_id OPERATOR(pg_catalog.=) o.system_id
      LEFT JOIN consentvault.contact_key k ON k.org_id OPERATOR(pg_catalog.=) o.org_id AND k.contact_fp OPERATOR(pg_catalog.=) o.contact_fp
     WHERE i.org_id OPERATOR(pg_catalog.=) consentvault.current_org() AND i.intent_id OPERATOR(pg_catalog.=) p_intent
       AND i.effect OPERATOR(pg_catalog.=) 'push' AND i.legacy_ref IS NOT NULL;
$$;
CREATE FUNCTION consentvault.any_organisation_cut_over() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM consentvault.effect_watermark);
$$;
GRANT CREATE ON SCHEMA consentvault TO consentvault_operator;
ALTER FUNCTION consentvault.effect_legacy_push_material(uuid) OWNER TO consentvault_operator;
ALTER FUNCTION consentvault.any_organisation_cut_over() OWNER TO consentvault_operator;
REVOKE CREATE ON SCHEMA consentvault FROM consentvault_operator;
GRANT SELECT ON consentvault.outbox, consentvault.connected_system, consentvault.contact_key, consentvault.effect_intent TO consentvault_operator;
REVOKE ALL ON FUNCTION consentvault.effect_legacy_push_material(uuid), consentvault.any_organisation_cut_over() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.effect_legacy_push_material(uuid) TO consentvault_worker;
GRANT EXECUTE ON FUNCTION consentvault.any_organisation_cut_over() TO consentvault_worker, consentvault_app;
