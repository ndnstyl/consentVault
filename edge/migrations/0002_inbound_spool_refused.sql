-- A post the vault refuses (4xx or a redirect) is closed as refused, kept for the record with its status, and no longer
-- counts toward the open caps; open means drained_at IS NULL AND refused_at IS NULL.
ALTER TABLE inbound_spool ADD COLUMN refused_at TEXT;
DROP INDEX inbound_spool_open;
DROP INDEX inbound_spool_number_open;
CREATE INDEX inbound_spool_open ON inbound_spool (drained_at, refused_at, received_at);
CREATE INDEX inbound_spool_number_open ON inbound_spool (number_key, drained_at, refused_at);
