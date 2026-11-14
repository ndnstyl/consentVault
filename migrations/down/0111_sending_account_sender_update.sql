-- Reverses 0111_sending_account_sender_update.sql: the runtime role can no longer update the sealed sender; stored senders are untouched.
BEGIN;
REVOKE UPDATE (sender_ct) ON consentvault.sending_account FROM consentvault_app;
COMMIT;
