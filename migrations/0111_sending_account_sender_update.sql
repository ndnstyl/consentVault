-- A text's To number that is not on the stored sender list is read from the provider once and the list is kept on the account
-- (confirm/inbound.py, _live_numbers). The runtime role could update every other column of sending_account but not the sealed
-- sender (sender_ct), so that write was refused by the database and the inbound post answered 503. This grants that one column.
-- The column is written, never read back as plaintext by a session; reads of it were already granted in 0047.
GRANT UPDATE (sender_ct) ON consentvault.sending_account TO consentvault_app;
