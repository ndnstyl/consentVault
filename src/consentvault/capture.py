"""Record a consumer's consent capture as a grant event."""

from __future__ import annotations

from typing import Iterable

import psycopg

from .errors import EmptyConsentError, UncheckedConsentError
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


def tenant_capture(
    conn: psycopg.Connection,
    crypto,
    *,
    contact: str,
    event_type: str,
    channels: Iterable[str],
    purposes: Iterable[str],
    method: str = "checkbox",
    origin: str = "consumer",
    checked: bool | None = None,
    contact_verification: str = "none",
    inbound_message: str | None = None,
    disclosure_sha256: str | None = None,
    payload: bytes | None = None,
    **fields,
) -> Event:
    """Record one event in the entered organisation's chain (hash version 2), with the core's capture rules.

    A grant needs the consent box checked, at least one channel and purpose, and wording; a verified grant needs the
    one-time code confirmed by the integrator (``otp``). A START text is refused. Stops carry no wording, and any verification
    claim or text sent with one is ignored. The caller has entered the tenant (``tenancy.tokens.org_transaction``).
    """
    from .errors import InvalidEventError
    from .ledger import record_tenant_event
    if event_type == "grant":
        if checked is not True:
            raise UncheckedConsentError("the consent box was not checked; no grant recorded")
        chans = [channels] if isinstance(channels, str) else [c for c in channels if c]
        purps = [purposes] if isinstance(purposes, str) else [p for p in purposes if p]
        if not chans or not purps:
            raise EmptyConsentError("a grant must name at least one channel and one purpose")
        if not disclosure_sha256:
            raise EmptyConsentError("a grant must carry the hash of the disclosure the person saw")
        channels, purposes = chans, purps
    elif checked is not None:
        raise InvalidEventError("'checked' belongs only to a grant")
    if event_type != "grant":
        contact_verification, inbound_message = "none", None  # a stop always records, whatever text came with it
    elif contact_verification == "inbound_keyword" or inbound_message is not None:
        raise InvalidEventError("a START text restores nothing; the way back is a form")
    return record_tenant_event(
        conn, crypto, contact=contact, event_type=event_type, channels=channels, purposes=purposes, method=method,
        origin=origin, disclosure_sha256=disclosure_sha256 or None, contact_verification=contact_verification,
        payload=payload, **fields)
