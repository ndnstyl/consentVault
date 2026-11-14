-- One bounce row per provider message: the alarm relay records a product-email bounce or complaint, then publishes its
-- alarm, then deletes the queued event. When the alarm cannot be published the event is delivered again; this index lets
-- the second write find the first (INSERT ... ON CONFLICT DO NOTHING) instead of adding a duplicate row. Our product email
-- has one recipient per message, so the provider's message id names one bounce.
CREATE UNIQUE INDEX notify_send_log_bounce_once ON consentvault.notify_send_log (provider, provider_message_id)
    WHERE outcome = 'bounced';
