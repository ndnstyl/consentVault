"""Record a consumer's consent capture as a grant event."""

from __future__ import annotations

from typing import Iterable

import psycopg

from .ledger import Event


def capture(
    conn: psycopg.Connection,
    *,
    contact: str,
    checked: bool,
    disclosure_sha256: str,
    channels: Iterable[str],
    purposes: Iterable[str],
    method: str = "checkbox",
    origin: str = "consumer",
    region: str | None = None,
    allowed_purposes=None,
    **fields,
) -> Event:
    """A caller in this process hands a submitted consent box to the one door: the request is stored whole as a post, and the
    post's event is returned. A box not checked, no channel or purpose, or no wording hash stores the post and raises the
    error that names which, with no event written."""
    from . import door

    payload = {"contact": contact, "event_type": "grant", "checked": checked, "disclosure_sha256": disclosure_sha256,
               "channels": [channels] if isinstance(channels, str) else list(channels),
               "purposes": [purposes] if isinstance(purposes, str) else list(purposes), "method": method, "origin": origin,
               **fields}
    return door.submit(conn, intake="library", payload=payload, region=region, allowed_purposes=allowed_purposes)


def revoke(
    conn: psycopg.Connection,
    *,
    contact: str,
    channels: Iterable[str],
    purposes: Iterable[str],
    method: str = "keyword",
    origin: str = "consumer",
    region: str | None = None,
    allowed_purposes=None,
    **fields,
) -> Event:
    """A caller in this process hands a person's stop to the one door: stored whole as a post, then its event is returned. A stop
    always counts, whatever text came with it."""
    from . import door

    payload = {"contact": contact, "event_type": "revoke", "channels": [channels] if isinstance(channels, str) else list(channels),
               "purposes": [purposes] if isinstance(purposes, str) else list(purposes), "method": method, "origin": origin,
               **fields}
    return door.submit(conn, intake="library", payload=payload, region=region, allowed_purposes=allowed_purposes)


def capture_verified(
    conn: psycopg.Connection,
    *,
    verification: str,
    inbound_message: str | None = None,
    **kwargs,
) -> Event:
    """A grant whose contact point the integrator verified (``verification`` is ``otp``: the integrator confirmed a one-time
    code; the vault records that they did). A START text (``inbound_keyword`` or an ``inbound_message``) is stored as a post
    and restores nothing: this raises, and the way back is a form."""
    from . import door

    region, allowed = kwargs.pop("region", None), kwargs.pop("allowed_purposes", None)
    payload = {"event_type": "grant", "method": "checkbox", "origin": "consumer", **kwargs, "contact_verification": verification}
    for name in ("channels", "purposes"):
        if isinstance(payload.get(name), str):
            payload[name] = [payload[name]]
    if inbound_message is not None:
        payload["inbound_message"] = inbound_message
    return door.submit(conn, intake="library", payload=payload, region=region, allowed_purposes=allowed)
