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


def capture_verified(
    conn: psycopg.Connection,
    *,
    verification: str,
    inbound_message: str | None = None,
    **kwargs,
) -> Event:
    """Record a grant whose contact point the integrator verified.

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
    if "checked" not in kwargs:
        raise InvalidEventError("a verified grant needs the consent box value the person sent (checked); it is never defaulted")
    kwargs.setdefault("method", "keyword" if verification == "inbound_keyword" else "checkbox")
    return capture(conn, contact_verification=verification, **kwargs)


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
    one-time code confirmed by the integrator (``otp``) or an inbound START keyword (``inbound_keyword``, the message
    is classified here). Stops carry no wording. The caller has entered the tenant (``tenancy.tokens.org_transaction``).
    """
    from .errors import InvalidEventError
    from .ledger import record_tenant_event
    from .stopwords import START, classify

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
    if contact_verification == "inbound_keyword":
        if not inbound_message:
            raise InvalidEventError("an inbound_keyword grant needs the inbound message (inbound_message)")
        verdict = classify(inbound_message)
        if verdict.verdict != START:
            raise InvalidEventError(
                f"the inbound message is not a START keyword (read as {verdict.verdict}: {verdict.reason})")
        if method == "checkbox":
            method = "keyword"
    elif inbound_message is not None:
        raise InvalidEventError("inbound_message belongs only to an inbound_keyword grant")
    return record_tenant_event(
        conn, crypto, contact=contact, event_type=event_type, channels=channels, purposes=purposes, method=method,
        origin=origin, disclosure_sha256=disclosure_sha256 or None, contact_verification=contact_verification,
        payload=payload, **fields)
