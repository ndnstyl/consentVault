-- Reverses 0107_legacy_push_material.sql.
BEGIN;
DROP FUNCTION consentvault.any_organisation_cut_over();
DROP FUNCTION consentvault.effect_legacy_push_material(uuid);
COMMIT;
