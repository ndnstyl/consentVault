-- Pure projection, item 21: ``confirmation_enqueue`` is refused by name once an organisation has cut over (its confirmation intents are
-- derived from its history rows), and with no organisation entered. The body the old fold calls is kept under a new name and still answers
-- for an organisation that has not cut over, so nothing the old fold uses stops working before its cutover.
ALTER FUNCTION consentvault.confirmation_enqueue(uuid, text) RENAME TO confirmation_enqueue_before_cutover;
CREATE FUNCTION consentvault.confirmation_enqueue(p_event_id uuid, p_contact_fp text) RETURNS integer
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF consentvault.current_org() IS NULL OR EXISTS (SELECT 1 FROM consentvault.effect_watermark
                                                      WHERE org_id OPERATOR(pg_catalog.=) consentvault.current_org()) THEN
        RAISE EXCEPTION 'consentvault confirmations: confirmation_enqueue is retired at the cutover; a confirmation is an effect intent derived from a history row'
            USING ERRCODE = 'feature_not_supported';
    END IF;
    RETURN consentvault.confirmation_enqueue_before_cutover(p_event_id, p_contact_fp);
END;
$$;
REVOKE ALL ON FUNCTION consentvault.confirmation_enqueue(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consentvault.confirmation_enqueue(uuid, text) TO consentvault_app;
REVOKE ALL ON FUNCTION consentvault.confirmation_enqueue_before_cutover(uuid, text) FROM PUBLIC, consentvault_app;
