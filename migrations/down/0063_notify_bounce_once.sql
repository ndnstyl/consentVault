-- Undo 0063: the one-bounce-row-per-message index goes; the rows stay.
DROP INDEX consentvault.notify_send_log_bounce_once;
