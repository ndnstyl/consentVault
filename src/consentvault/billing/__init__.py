"""Billing: Stripe hosted pages only, the once-only webhook, the daily usage report.

Nothing about payment is stored but Stripe ids and plan facts. Capture is never refused for non-payment: a late or
cancelled subscription changes the organisation's status and nothing here stops a consent event being recorded.
"""
