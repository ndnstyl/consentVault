"""Stripe webhook signature check: ``Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>]``.

The signed string is ``<t>.<raw body>`` under HMAC-SHA256 with the endpoint's signing secret. A timestamp outside the
tolerance is refused as stale (a captured request cannot be replayed later).
"""

from __future__ import annotations

import hashlib
import hmac
import time

from .errors import WebhookSignatureError

TOLERANCE_SECONDS = 300


def sign_payload(secret: str, payload: bytes, timestamp: int) -> str:
    """The v1 signature Stripe computes (used by tests to build genuine and forged requests)."""
    return hmac.new(secret.encode("utf-8"), str(timestamp).encode("ascii") + b"." + payload, hashlib.sha256).hexdigest()


def verify_signature(payload: bytes, header: str | None, secret: str, *, now: float | None = None,
                     tolerance: int = TOLERANCE_SECONDS) -> int:
    """Return the signed timestamp, or raise ``WebhookSignatureError`` naming what is wrong."""
    if not secret:
        raise WebhookSignatureError("the webhook signing secret is not configured; refusing every webhook")
    if not header:
        raise WebhookSignatureError("the Stripe-Signature header is missing")
    timestamp: int | None = None
    candidates: list[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError:
                raise WebhookSignatureError("the Stripe-Signature timestamp is not a number") from None
        elif key == "v1" and value:
            candidates.append(value)
    if timestamp is None or not candidates:
        raise WebhookSignatureError("the Stripe-Signature header has no timestamp or no v1 signature")
    current = time.time() if now is None else now
    if abs(current - timestamp) > tolerance:
        raise WebhookSignatureError(f"the Stripe-Signature timestamp is outside the {tolerance}s tolerance")
    expected = sign_payload(secret, payload, timestamp)
    if not any(hmac.compare_digest(c.encode("utf-8"), expected.encode("utf-8")) for c in candidates):
        raise WebhookSignatureError("the Stripe-Signature does not match the body")
    return timestamp
