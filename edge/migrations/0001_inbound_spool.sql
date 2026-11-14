-- The gateway's inbound store (D1 database consentvault-inbound-spool, binding INBOUND_SPOOL): every post to the number's
-- fallback address is stored here before the vault is asked, and marked drained only when the vault answers it with a 2xx.
CREATE TABLE inbound_spool (
  id           TEXT PRIMARY KEY,
  number_key   TEXT NOT NULL,          -- the sending account's inbound key (the address Twilio posted to)
  received_at  TEXT NOT NULL,          -- ISO 8601, UTC, the edge's arrival time
  path         TEXT NOT NULL,          -- the fallback path the vault is posted to again
  body_b64     TEXT NOT NULL,          -- the raw body, byte for byte
  headers_json TEXT NOT NULL,          -- the provider headers that carry the signature (content-type, x-twilio-signature, ...)
  attempts     INTEGER NOT NULL DEFAULT 0,
  last_status  INTEGER,                -- the vault's last answer
  drained_at   TEXT                    -- set only on the vault's 2xx; NULL while open
);
CREATE INDEX inbound_spool_open ON inbound_spool (drained_at, received_at);
CREATE INDEX inbound_spool_number_open ON inbound_spool (number_key, drained_at);
