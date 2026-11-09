-- Reverses 0081_site_key_state_times.sql: the times lookup goes; the projection then judges a site key by its state now again.
BEGIN;
DROP FUNCTION consentvault.resolve_site_key_times(text);
REVOKE SELECT (retired_at) ON consentvault.capture_source FROM consentvault_operator;
COMMIT;
