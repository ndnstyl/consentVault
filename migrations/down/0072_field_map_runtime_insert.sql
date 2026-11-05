-- Reverses 0069_field_map_runtime_insert.sql: the runtime role reads form field maps and no longer adds a version.
BEGIN;

REVOKE INSERT ON consentvault.form_field_map FROM consentvault_app;

COMMIT;
