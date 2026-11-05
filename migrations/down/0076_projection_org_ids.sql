-- Reverses 0076_projection_org_ids.sql: the rebuild job can no longer list the organisations to project. Nothing stored is touched.
BEGIN;
DROP FUNCTION consentvault.projection_org_ids();
COMMIT;
