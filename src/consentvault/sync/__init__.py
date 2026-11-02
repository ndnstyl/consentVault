"""ConsentVault sync layer (multi-tenant cloud build): suppression sync outbox, worker, connector and routes.

For the capture code (API lane): call ``consentvault.sync.outbox.enqueue_event_pushes`` inside the transaction that
inserts the event, right after the INSERT. See that function's docstring for the exact contract.
"""
