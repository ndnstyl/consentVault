-- Reverses 0093_projection_login.sql: the role keeps no privilege on the vault and the sync function goes. The role itself and its
-- membership are the superuser's to drop (DROP ROLE consentvault_projection), as they made them.
BEGIN;
REVOKE ALL ON ALL TABLES IN SCHEMA consentvault FROM consentvault_projection;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA consentvault FROM consentvault_projection;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA consentvault FROM consentvault_projection;
REVOKE ALL ON SCHEMA consentvault FROM consentvault_projection;
DROP FUNCTION consentvault.grant_projection_privileges();
COMMIT;
