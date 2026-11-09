-- Reverses 0093_pending_invites_for_address.sql: the pre-tenant lookup goes; invitations and memberships are untouched.
BEGIN;
DROP FUNCTION consentvault.invite_pending_for_email(text);
COMMIT;
