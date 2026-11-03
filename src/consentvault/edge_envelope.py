"""The capture edge's forward envelope (contracts/capture-api.md section 5), read by the vault.

The edge forwards the browser's own request, not a rebuilt event: method, path, query, every header as the runtime
presented it, the exact bytes of the body (``body_b64``) with its SHA-256 and byte count, and what the edge itself saw
(``edge_facts``). It signs ``<timestamp>.<envelope text>`` with the edge secret. Only an envelope whose signature verified
is unpacked; any other request is stored exactly as received and nothing in it is trusted.

Nothing here judges the browser's request: a body that is garbage unpacks as garbage and is stored whole.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime

from .errors import ConsentVaultError


class EnvelopeUnreadable(ConsentVaultError):
    """The signed envelope is not shaped as the contract says (the signed bytes are stored as received)."""


@dataclass(frozen=True)
class Unpacked:
    method: str
    path: str
    query: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    edge_facts: dict
    claimed_sha256: str | None
    edge_received_at: datetime | None


def signature(secret: bytes | str, timestamp: str, body: bytes) -> str:
    key = secret if isinstance(secret, bytes) else secret.encode("utf-8")
    return hmac.new(key, timestamp.encode("ascii", "replace") + b"." + body, hashlib.sha256).hexdigest()


def verified(secret: bytes | str | None, timestamp: str, sent: str, body: bytes) -> bool:
    """True only when the edge's HMAC over ``<timestamp>.<body>`` matches (constant time)."""
    if not secret or not timestamp or not sent:
        return False
    return hmac.compare_digest(sent.strip().lower().encode("utf-8"), signature(secret, timestamp, body).encode("utf-8"))


def looks_like_envelope(body: bytes) -> bool:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):  # loud-failure-exempt: a body that is not JSON is not an envelope; it is stored as received
        return False
    return isinstance(parsed, dict) and "body_b64" in parsed and "headers" in parsed


def _text(env: dict, name: str) -> str:
    value = env.get(name)
    if not isinstance(value, str):
        raise ValueError(f"the envelope's {name} is not text")
    return value


def unpack(body: bytes) -> Unpacked:
    """The browser's request inside a signed envelope, read strictly: nothing is defaulted and no type is changed. An envelope
    that is not shaped as the contract says raises ``EnvelopeUnreadable`` (the caller still stores the signed bytes)."""
    try:
        env = json.loads(body.decode("utf-8"))
        if not isinstance(env, dict):
            raise ValueError("the envelope is not an object")
        raw = base64.b64decode(_text(env, "body_b64"), validate=True)
        raw_headers = env.get("headers")
        if not isinstance(raw_headers, list) or not all(
                isinstance(h, list) and len(h) == 2 and all(isinstance(x, str) for x in h) for h in raw_headers):
            raise ValueError("the envelope's headers are not a list of name and value pairs")
        facts = env.get("edge_facts")
        if not isinstance(facts, dict):
            raise ValueError("the envelope's edge_facts is not an object")
        claimed = env.get("body_sha256")
        if claimed is not None and not isinstance(claimed, str):
            raise ValueError("the envelope's body_sha256 is not text")
        method, path, query = _text(env, "method"), _text(env, "path"), _text(env, "query")
    except (ValueError, UnicodeDecodeError, TypeError, binascii.Error) as exc:
        raise EnvelopeUnreadable(f"the edge envelope could not be read: {type(exc).__name__}") from exc
    seen = None
    if isinstance(facts.get("edge_received_at"), str):
        try:
            seen = datetime.fromisoformat(facts["edge_received_at"].replace("Z", "+00:00"))
        except ValueError:  # loud-failure-exempt: the edge's own text is kept whole as the edge fact edge_received_at
            seen = None
    return Unpacked(method, path, query, tuple((n, v) for n, v in raw_headers), raw, facts, claimed, seen)


def widget_event(browser: dict, headers, edge_facts: dict, *, source_id=None, brand_ids=None, source: str | None = None) -> dict:
    """The event fields a browser widget's own post carries, for the transitional derivation: its contact, box, channels,
    purposes and wording hash, with what the edge saw (address, arrival time, bot-check answer) beside them. The stored post
    is the browser's bytes; this reads from them and changes none."""
    answer = edge_facts.get("bot_check_answer")
    event = {
        "contact": browser.get("contact"), "event_type": "grant", "method": "checkbox", "origin": "consumer",
        "contact_verification": "none", "channels": browser.get("channels"), "purposes": browser.get("purposes"),
        "disclosure_sha256": browser["disclosure_sha256"].lower() if isinstance(browser.get("disclosure_sha256"), str) else browser.get("disclosure_sha256"),
        "page_url": browser.get("page_url"),
        "session_ref": browser.get("session"), "edge_received_at": edge_facts.get("edge_received_at"),
        "client_ip": edge_facts.get("client_ip"),
        "user_agent": next((v for n, v in headers if n.lower() == "user-agent"), None),
        "bot_check": "turnstile:pass" if isinstance(answer, dict) and answer.get("success") is True else None,
        "source": source or edge_facts.get("source_label") or "site_key",
        "source_id": str(source_id) if source_id is not None else None, "brand_ids": list(brand_ids) if brand_ids else None,
    }
    if "checked" in browser:
        event["checked"] = browser["checked"]
    return {k: v for k, v in event.items() if v is not None}
