-- Undo 0061: the workflow credential goes. Refuses while a credential is live, so a Twenty workflow is never cut off silently.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM consentvault.workflow_credential WHERE revoked_at IS NULL
                  AND consentvault.workflow_credential_end(expires_at, overlap_until) > clock_timestamp()) THEN
        RAISE EXCEPTION 'undo 0061 refused: a workflow credential is still live; revoke it first' USING ERRCODE = 'object_in_use';
    END IF;
END
$$;
DROP FUNCTION consentvault.workflow_credential_reminders_due();
DROP FUNCTION consentvault.workflow_credential_use(text);
DROP FUNCTION consentvault.workflow_credential_revoke(uuid, uuid);
DROP TRIGGER workflow_credential_disconnect ON consentvault.connected_system;
DROP FUNCTION consentvault.workflow_credential_disconnect();
DROP FUNCTION consentvault.workflow_credential_issue(uuid, text, text);
DROP TABLE consentvault.workflow_credential;
DROP FUNCTION consentvault.workflow_credential_end(timestamptz, timestamptz);
