"""Record a consumer's consent capture as a grant event."""

from __future__ import annotations

from typing import Iterable

import psycopg

from .safelog import describe
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
        return ev, None, f"{describe(exc)}"
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

    ``verification`` is ``otp`` (the integrator confirmed a one-time code sent to the contact point). The vault records
    that the integrator verified it; sending and checking the code is the integrator's job and the vault cannot see it.
    A START text (``inbound_keyword``) restores nothing: it is refused here, and the way back is a form.
    """
    from .errors import InvalidEventError

    if verification == "inbound_keyword" or inbound_message is not None:
        raise InvalidEventError("a START text restores nothing; the way back is a form (verification 'otp' or none)")
    if verification != "otp":
        raise InvalidEventError("verification must be 'otp'")
    if "checked" not in kwargs:
        raise InvalidEventError("a verified grant needs the consent box value the person sent (checked); it is never defaulted")
    kwargs.setdefault("method", "checkbox")
    return capture_and_release(conn, contact_verification=verification, **kwargs)


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
