-- Pure projection, effects: everything the push of one derived intent needs, read in the entered organisation by the worker, which holds
-- no grant on the connected system, the history or the contact key. A definer; it returns what the push is built from and nothing else.
CREATE FUNCTION consentvault.effect_push_material(p_intent uuid)
    RETURNS TABLE (system_id uuid, system_name text, endpoint text, signature text, credentials_ct bytea, contact_form text, system_status text,
                   event_id uuid, event_type text, channels text[], purposes text[], placed_at timestamptz, contact_fp text,
                   contact_ct bytea, wrapped_key bytea, key_version integer)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT s.system_id, s.name, s.endpoint, s.signature, s.credentials_ct, s.contact_form, s.status,
           h.event_id, h.event_type_sent, h.channels_sent, h.purposes_sent, h.placed_at, h.contact_fp, h.contact_ct,
           k.wrapped_key, k.key_version
      FROM consentvault.effect_intent i
      JOIN consentvault.connected_system s ON s.org_id OPERATOR(pg_catalog.=) i.org_id AND s.system_id::pg_catalog.text OPERATOR(pg_catalog.=) i.target
      JOIN consentvault.post_history h ON h.org_id OPERATOR(pg_catalog.=) i.org_id AND h.post_id OPERATOR(pg_catalog.=) i.post_id
      LEFT JOIN consentvault.contact_key k ON k.org_id OPERATOR(pg_catalog.=) h.org_id AND k.contact_fp OPERATOR(pg_catalog.=) h.contact_fp
     WHERE i.org_id OPERATOR(pg_catalog.=) consentvault.current_org() AND i.intent_id OPERATOR(pg_catalog.=) p_intent AND i.effect OPERATOR(pg_catalog.=) 'push';
$$;
REVOKE ALL ON FUNCTION consentvault.effect_push_material(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.effect_push_material(uuid) TO consentvault_worker;

-- The cutover job runs as the operator console login: it writes the watermark row of each organisation (the facts it then writes go through the
-- ordinary writer under that organisation's token).
GRANT SELECT, INSERT ON consentvault.effect_watermark TO consentvault_operator, consentvault_console;
GRANT EXECUTE ON FUNCTION consentvault.sync_targets(), consentvault.confirmation_rules_enabled() TO consentvault_console;
