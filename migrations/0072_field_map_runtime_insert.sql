-- The admin API adds a new version of a form's field map as the runtime role (a version is a new row; nothing is ever updated).
-- Only the columns a caller states are insertable: the map id and the time the map was set are stamped by the database.
BEGIN;

GRANT INSERT (org_id, source_id, map_version, consent_ticked_value, body_format, consent_paths, decision_time_path, wording_path,
    wording_hash_path, seller_paths, form_version_path, checkbox_default_path, submit_context_path, third_party_cert_path,
    jurisdiction_path, channel_scope_path, contact_paths, set_by) ON consentvault.form_field_map TO consentvault_app;

COMMIT;
