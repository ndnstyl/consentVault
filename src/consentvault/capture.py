"""Record a consumer's consent capture as a grant event."""

from __future__ import annotations

from typing import Iterable

import psycopg

from .errors import EmptyConsentError, UncheckedConsentError
from .ledger import Event, record_event


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
    **fields,
) -> Event:
    """Turn a submitted consent box into a grant. Unchecked or empty consent is refused."""
    if checked is not True:
        raise UncheckedConsentError("the consent box was not checked; no grant recorded")
    chans = [channels] if isinstance(channels, str) else [c for c in channels if c]
    purps = [purposes] if isinstance(purposes, str) else [p for p in purposes if p]
    if not chans or not purps:
        raise EmptyConsentError("a grant must name at least one channel and one purpose")
    if not disclosure_sha256:
        raise EmptyConsentError("a grant must carry the hash of the disclosure the person saw")
    return record_event(
        conn,
        contact=contact,
        event_type="grant",
        channels=chans,
        purposes=purps,
        method=method,
        origin=origin,
        disclosure_sha256=disclosure_sha256,
        **fields,
    )


def capture_and_release(conn: psycopg.Connection, **kwargs) -> tuple[Event, dict | None, str | None]:
    """Record a grant, then run the release rule for a consumer grant.

    Returns ``(grant, release, release_error)``. ``release`` is ``{"released_channels": [...], "refusals":
    {cause: [channels]}}`` for a consumer grant and ``None`` for any other origin. When the decision itself cannot
    be written the grant stays recorded and ``release_error`` names the failure, so callers can surface the error.
    """
    from .errors import ConsentVaultError
    from .release import release_after_grant

    ev = capture(conn, **kwargs)
    if kwargs.get("origin", "consumer") != "consumer":
        return ev, None, None
    try:
        res = release_after_grant(conn, ev.event_id)
    except ConsentVaultError as exc:
        return ev, None, f"{type(exc).__name__}: {exc}"
    return ev, {"released_channels": list(res.released_channels),
                "refusals": {c: list(v) for c, v in res.refusals.items()}}, None


def capture_verified(
    conn: psycopg.Connection,
    *,
    verification: str,
    inbound_message: str | None = None,
    **kwargs,
) -> tuple[Event, dict | None, str | None]:
    """Record a grant whose contact point the integrator verified, then run the release rule.

    ``verification`` is ``otp`` (the integrator confirmed a one-time code sent to the contact point) or
    ``inbound_keyword`` (the contact point itself sent a START-type message, passed as ``inbound_message`` and
    checked here with the stop-word classifier). The vault records that the integrator verified it; sending and
    checking the code is the integrator's job and the vault cannot see it.
    """
    from .errors import InvalidEventError
    from .stopwords import START, classify

    if verification not in ("otp", "inbound_keyword"):
        raise InvalidEventError("verification must be 'otp' or 'inbound_keyword'")
    if verification == "inbound_keyword":
        if not inbound_message:
            raise InvalidEventError("an inbound_keyword grant needs the inbound message (inbound_message)")
        verdict = classify(inbound_message)
        if verdict.verdict != START:
            raise InvalidEventError(
                f"the inbound message is not a START keyword (read as {verdict.verdict}: {verdict.reason})")
    elif inbound_message is not None:
        raise InvalidEventError("inbound_message belongs only to an inbound_keyword grant")
    kwargs.setdefault("method", "keyword" if verification == "inbound_keyword" else "checkbox")
    kwargs.setdefault("checked", True)
    return capture_and_release(conn, contact_verification=verification, **kwargs)
