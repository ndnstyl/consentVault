"""Generic signed outbound webhook: a CrmAdapter that POSTs each permission change as JSON.

The receiver verifies ``X-ConsentVault-Signature`` = HMAC-SHA256 hex over ``timestamp + "." + body`` using the
shared secret, and may reject timestamps older than its own tolerance.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from typing import Callable

from ..errors import ConsentVaultError
from .base import PermissionChange


class AdapterError(ConsentVaultError):
    """An adapter could not deliver or pull."""


def sign(secret: str, timestamp: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


def change_to_dict(change: PermissionChange) -> dict:
    return {
        "event_id": change.event_id,
        "contact_norm": change.contact_norm,
        "contact_kind": change.contact_kind,
        "channel": change.channel,
        "purpose": change.purpose,
        "allowed": change.allowed,
        "reason": change.reason,
        "changed_at": change.changed_at.isoformat() if change.changed_at else None,
    }


class WebhookCrmAdapter:
    name = "webhook"

    def __init__(
        self,
        url: str,
        secret: str,
        timeout: float = 10.0,
        opener: Callable[..., object] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not url:
            raise AdapterError("webhook adapter needs a url")
        if not secret:
            raise AdapterError("webhook adapter needs a signing secret")
        self.url = url
        self.secret = secret
        self.timeout = timeout
        self._open = opener or urllib.request.urlopen
        self._clock = clock

    def push_permission_change(self, change: PermissionChange) -> None:
        body = json.dumps(change_to_dict(change), sort_keys=True, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(self._clock()))
        req = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-ConsentVault-Timestamp": timestamp,
                "X-ConsentVault-Signature": sign(self.secret, timestamp, body),
            },
        )
        try:
            resp = self._open(req, timeout=self.timeout)
            status = getattr(resp, "status", None) or resp.getcode()
        except urllib.error.HTTPError as exc:
            raise AdapterError(f"webhook {self.url} answered {exc.code}; change not delivered") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise AdapterError(f"webhook {self.url} unreachable: {exc}; change not delivered") from exc
        if not 200 <= int(status) < 300:
            raise AdapterError(f"webhook {self.url} answered {status}; change not delivered")
