-- Pure projection, cutover reads. The enabled confirmation rules of the entered organisation, for the intake to capture as a fact at
-- arrival (the fold reads the fact, never the table). A definer: the runtime role holds no grant on the rule table.
CREATE FUNCTION consentvault.confirmation_rules_enabled() RETURNS TABLE (source_id uuid, channel text, sending_brand_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT r.source_id, r.channel, r.sending_brand_id FROM consentvault.confirmation_rule r
     WHERE r.org_id OPERATOR(pg_catalog.=) consentvault.current_org() AND r.enabled ORDER BY r.source_id, r.channel;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_rules_enabled() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_rules_enabled() TO consentvault_app, consentvault_worker;
