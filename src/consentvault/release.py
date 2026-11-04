"""The release rule.

A later consumer grant lifts the consumer's OWN earlier stop, for the channels the grant's
disclosure names and no others. Never staff, regulatory or imported stops, never a stop made by a
method outside keyword/checkbox/written. A release needs a held disclosure and a session
reference; optionally it also needs that nobody contacted the person on that channel since the stop.

A form grant from the person after their own stop takes effect: the rule asks for no verification of the contact point and
opens no review row. A text never lifts a stop.

The quiet window ignores the contact-log rows the confirmation service wrote (``recorded_by = 'confirmations'``): its opt-out, HELP and
START replies each answer the person's own message, so none of them is contact since the stop (confirmations.md, core change C2).

A stop that arrived after the grant is never lifted by it: the decision is refused with cause ``stop_after_grant``,
and the view ranks a release at the position of its grant, so the same holds for any release row.

Every decision about a consumer grant is written to the ledger as a ``release`` event (the ledger accepts a release
row only for a consumer grant, so a refusal of a staff, regulatory or import grant is returned to the caller and not
stored) with explicit columns:
``release_of_event_id`` is the grant decided, ``release_outcome`` is ``released`` or ``refused``, and
``release_cause`` names the refusal. Only released decisions lift a stop in ``consentvault.current_permission``.
A stop recorded after the grant outranks the release, because the view orders events by arrival (``seq``).
The quiet window uses the vault's own clock and ``seq``: the contact log's ``recorded_at`` between the stop's and
the grant's ``received_at``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import psycopg

from .safelog import describe
from .errors import ConsentVaultError, InvalidEventError
from .ledger import record_event

ENV_REQUIRE_NO_CONTACT = "CONSENTVAULT_RELEASE_REQUIRE_NO_CONTACT_SINCE_STOP"
RELEASABLE_STOP_METHODS = ("keyword", "checkbox", "written")
RELEASER = "consentvault.release"
RELEASE_SOURCE = "release"

CAUSE_NOT_CONSUMER_GRANT = "grant_not_from_consumer"
CAUSE_NO_DISCLOSURE = "no_held_disclosure"
CAUSE_NO_SESSION = "no_session_ref"
CAUSE_NOT_OWN_STOP = "stop_not_consumers_own"
CAUSE_NOT_IN_DISCLOSURE = "channel_not_in_disclosure"
CAUSE_NO_PURPOSE_OVERLAP = "purpose_not_in_disclosure"
CAUSE_CONTACT_SINCE_STOP = "contact_since_stop"
CAUSE_STOP_AFTER_GRANT = "stop_after_grant"
LEDGER_LOCK_SQL = "SELECT pg_advisory_xact_lock(hashtext('consentvault.ledger'))"


@dataclass(frozen=True)
class ReleaseResult:
    released_channels: tuple[str, ...] = ()
    refusals: dict[str, tuple[str, ...]] = field(default_factory=dict)
    event_ids: tuple[str, ...] = ()

    @property
    def released(self) -> bool:
        return bool(self.released_channels)


def _require_no_contact(flag: bool | None) -> bool:
    if flag is not None:
        return flag
    return os.environ.get(ENV_REQUIRE_NO_CONTACT, "").strip().lower() in ("1", "true", "yes", "on")


def release_after_grant(
    conn: psycopg.Connection,
    grant_event_id: str,
    *,
    require_no_contact_since_stop: bool | None = None,
) -> ReleaseResult:
    """Decide, and write, the release decision for one consumer grant. Idempotent per grant."""
    try:
        with conn.transaction():
            conn.execute(LEDGER_LOCK_SQL)
            return _decide(conn, grant_event_id, require_no_contact_since_stop)
    except psycopg.Error as exc:
        raise ConsentVaultError(f"release decision refused by the database: {describe(exc)}") from exc


def _decide(conn, grant_event_id, require_no_contact_since_stop) -> ReleaseResult:
    require_quiet = _require_no_contact(require_no_contact_since_stop)
    try:
        grant = conn.execute("SELECT * FROM consentvault.event WHERE event_id = %s::uuid", (str(grant_event_id),)).fetchone()
    except psycopg.Error as exc:
        raise ConsentVaultError(f"cannot read the grant event: {describe(exc)}") from exc
    if grant is None:
        raise InvalidEventError(f"no event {grant_event_id!r} in the ledger")
    if grant["event_type"] != "grant":
        raise InvalidEventError(f"event {grant_event_id!r} is a {grant['event_type']}, not a grant")
    gid = str(grant["event_id"])

    prior = conn.execute(
        "SELECT event_id::text AS event_id FROM consentvault.event"
        " WHERE event_type = 'release' AND release_of_event_id = %s::uuid ORDER BY seq",
        (gid,),
    ).fetchall()
    if prior:
        return _result_from_events(conn, [p["event_id"] for p in prior])

    stops = conn.execute(
        "SELECT event_id, channels, purposes, origin, method, received_at, seq FROM consentvault.event"
        " WHERE event_type IN ('revoke', 'suppress') AND contact_kind = %s AND contact_norm = %s"
        " AND seq < %s ORDER BY seq",
        (grant["contact_kind"], grant["contact_norm"], grant["seq"]),
    ).fetchall()
    stopped_after = conn.execute(
        "SELECT 1 FROM consentvault.event WHERE event_type IN ('revoke', 'suppress') AND contact_kind = %s"
        " AND contact_norm = %s AND seq > %s LIMIT 1",
        (grant["contact_kind"], grant["contact_norm"], grant["seq"]),
    ).fetchone() is not None

    disclosure = None
    if grant["disclosure_sha256"]:
        disclosure = conn.execute(
            "SELECT channels, purposes FROM consentvault.disclosure WHERE sha256 = %s", (grant["disclosure_sha256"],)
        ).fetchone()

    def quiet_broken(channel: str, channel_stops: list[dict]) -> bool:
        return conn.execute(
            "SELECT 1 FROM consentvault.contact_log WHERE contact_kind = %s AND contact_norm = %s AND channel = %s"
            " AND coalesce(recorded_by, '') <> 'confirmations' AND recorded_at > %s AND recorded_at <= %s LIMIT 1",
            (grant["contact_kind"], grant["contact_norm"], channel,
             channel_stops[-1]["received_at"], grant["received_at"]),
        ).fetchone() is not None

    released, refused, released_purposes = _judge(
        grant, stops, stopped_after, disclosure, bool((grant["session_ref"] or "").strip()),
        quiet_broken if require_quiet else None)

    ids: list[str] = []

    def write(channels: list[str], purposes: list[str], outcome: str, cause: str | None = None) -> None:
        ev = record_event(
            conn,
            contact=grant["contact_norm"],
            contact_kind=grant["contact_kind"],
            event_type="release",
            channels=channels,
            purposes=purposes,
            method=grant["method"],
            origin="consumer",
            disclosure_sha256=grant["disclosure_sha256"],
            subject_key=grant["subject_key"],
            captured_at=grant["captured_at"],
            session_ref=grant["session_ref"],
            source=RELEASE_SOURCE,
            recorded_by=RELEASER,
            release_of_event_id=gid,
            release_outcome=outcome,
            release_cause=cause,
        )
        ids.append(ev.event_id)

    if released:
        write(released, released_purposes, "released")
    for cause in sorted(refused):
        if grant["origin"] != "consumer":
            continue  # the ledger accepts a release row only for a consumer grant; the refusal is returned, not stored
        write(refused[cause], list(grant["purposes"]), "refused", cause)
    return ReleaseResult(
        released_channels=tuple(released),
        refusals={c: tuple(v) for c, v in refused.items()},
        event_ids=tuple(ids),
    )


def _judge(grant: dict, stops: list[dict], stopped_after: bool, disclosure: dict | None, has_session: bool,
           quiet_broken) -> tuple[list[str], dict[str, list[str]], list[str]]:
    """The release rule for one grant, shared by the single-company and the tenant ledgers.

    Returns (released channels, {cause: [channels]}, purposes a release names). ``quiet_broken(channel, stops)`` is
    given only when the quiet window is required, and answers whether anyone contacted the person since the stop.
    """
    released: list[str] = []
    refused: dict[str, list[str]] = {}

    def refuse(cause: str, channel: str) -> None:
        refused.setdefault(cause, []).append(channel)

    released_purposes = list(grant["purposes"])
    for channel in sorted(grant["channels"]):
        channel_stops = [
            s for s in stops
            if channel in s["channels"] and ("*" in s["purposes"] or set(s["purposes"]) & set(grant["purposes"]))
        ]
        if not channel_stops:
            continue
        if stopped_after:
            refuse(CAUSE_STOP_AFTER_GRANT, channel)
        elif grant["origin"] != "consumer" or grant["method"] in ("staff", "import"):
            refuse(CAUSE_NOT_CONSUMER_GRANT, channel)
        elif disclosure is None:
            refuse(CAUSE_NO_DISCLOSURE, channel)
        elif not has_session:
            refuse(CAUSE_NO_SESSION, channel)
        elif any(s["origin"] != "consumer" or s["method"] not in RELEASABLE_STOP_METHODS for s in channel_stops):
            refuse(CAUSE_NOT_OWN_STOP, channel)
        elif channel not in disclosure["channels"]:
            refuse(CAUSE_NOT_IN_DISCLOSURE, channel)
        elif not (set(grant["purposes"]) & set(disclosure["purposes"])):
            refuse(CAUSE_NO_PURPOSE_OVERLAP, channel)
        elif quiet_broken is not None and quiet_broken(channel, channel_stops):
            refuse(CAUSE_CONTACT_SINCE_STOP, channel)
        else:
            released.append(channel)
    if disclosure is not None:
        released_purposes = sorted(set(grant["purposes"]) & set(disclosure["purposes"])) or released_purposes
    return released, refused, released_purposes


def _result_from_events(conn: psycopg.Connection, event_ids: list[str]) -> ReleaseResult:
    released: list[str] = []
    refusals: dict[str, tuple[str, ...]] = {}
    for eid in event_ids:
        row = conn.execute(
            "SELECT channels, release_outcome, release_cause FROM consentvault.event WHERE event_id = %s::uuid",
            (eid,),
        ).fetchone()
        outcome, cause = row["release_outcome"], row["release_cause"]
        if outcome == "released":
            released.extend(row["channels"])
        else:
            refusals[cause] = tuple(row["channels"])
    return ReleaseResult(tuple(released), refusals, tuple(event_ids))


TENANT_LOCK_SQL = "SELECT pg_advisory_xact_lock(consentvault.ledger_lock_key(consentvault.current_org()))"


def release_after_tenant_grant(
    conn: psycopg.Connection,
    crypto,
    grant_event_id: str,
    *,
    require_no_contact_since_stop: bool | None = None,
) -> ReleaseResult:
    """The release rule for a grant in the entered organisation's chain (hash version 2). Idempotent per grant.

    Same rule as ``release_after_grant``; the contact is matched by its keyed fingerprint, the decision rows are written
    through ``record_tenant_event`` and the review row keeps the contact and message only as ciphertext under the
    contact's key. Needs a token that may read evidence rows (a read scope); a capture token alone cannot.
    """
    try:
        with conn.transaction():
            conn.execute(TENANT_LOCK_SQL)
            return _decide_tenant(conn, crypto, grant_event_id, _require_no_contact(require_no_contact_since_stop))
    except psycopg.Error as exc:
        raise ConsentVaultError(f"release decision refused by the database: {describe(exc)}") from exc


def _decide_tenant(conn, crypto, grant_event_id, require_quiet: bool) -> ReleaseResult:
    import uuid as _uuid

    from .ledger import record_tenant_event
    from .tenancy import crypto as tc
    from .tenancy.errors import ContactKeyMissingError
    from .tenancy.keys_protocol import WrappedKey

    grant = conn.execute("SELECT * FROM consentvault.event WHERE org_id = consentvault.current_org()"
                         " AND event_id = %s::uuid", (str(grant_event_id),)).fetchone()
    if grant is None:
        raise InvalidEventError(f"no event {grant_event_id!r} in this organisation's ledger")
    if grant["event_type"] != "grant":
        raise InvalidEventError(f"event {grant_event_id!r} is a {grant['event_type']}, not a grant")
    if grant["hash_version"] != 2:
        raise InvalidEventError(f"event {grant_event_id!r} is a single-company row; use release_after_grant")
    gid, org, fp = str(grant["event_id"]), grant["org_id"], grant["contact_fp"]

    prior = conn.execute(
        "SELECT event_id::text AS event_id FROM consentvault.event WHERE org_id = consentvault.current_org()"
        " AND event_type = 'release' AND release_of_event_id = %s::uuid ORDER BY seq", (gid,)).fetchall()
    if prior:
        return _result_from_events(conn, [p["event_id"] for p in prior])

    stops = conn.execute(
        "SELECT event_id, channels, purposes, origin, method, received_at, seq FROM consentvault.event"
        " WHERE org_id = consentvault.current_org() AND event_type IN ('revoke', 'suppress')"
        " AND contact_kind = %s AND contact_fp = %s AND seq < %s ORDER BY seq",
        (grant["contact_kind"], fp, grant["seq"])).fetchall()
    stopped_after = conn.execute(
        "SELECT 1 FROM consentvault.event WHERE org_id = consentvault.current_org()"
        " AND event_type IN ('revoke', 'suppress') AND contact_kind = %s AND contact_fp = %s AND seq > %s LIMIT 1",
        (grant["contact_kind"], fp, grant["seq"])).fetchone() is not None
    disclosure = None
    if grant["disclosure_sha256"]:
        disclosure = conn.execute(
            "SELECT channels, purposes FROM consentvault.disclosure WHERE org_id = consentvault.current_org()"
            " AND sha256 = %s", (grant["disclosure_sha256"],)).fetchone()

    held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (fp,)).fetchone()
    if held is None:
        raise ContactKeyMissingError("the grant's contact has no data key (erased); its release cannot be decided")
    dk = crypto.open_contact_key(org, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))

    def plain(column: str, ct_column: str) -> str | None:
        blob = grant[ct_column]
        return None if blob is None else tc.decrypt_text(dk, org, gid, column, bytes(blob))

    norm = plain("contact_norm", "contact_ct")
    session = plain("session_ref", "session_ref_ct")

    def quiet_broken(channel: str, channel_stops: list[dict]) -> bool:
        return conn.execute(
            "SELECT 1 FROM consentvault.contact_log WHERE org_id = consentvault.current_org() AND contact_kind = %s"
            " AND contact_fp = %s AND channel = %s AND coalesce(recorded_by, '') <> 'confirmations'"
            " AND recorded_at > %s AND recorded_at <= %s LIMIT 1",
            (grant["contact_kind"], fp, channel, channel_stops[-1]["received_at"], grant["received_at"]),
        ).fetchone() is not None

    released, refused, released_purposes = _judge(
        grant, stops, stopped_after, disclosure, bool((session or "").strip()),
        quiet_broken if require_quiet else None)
    if grant["origin"] != "consumer":
        return ReleaseResult((), {c: tuple(v) for c, v in refused.items()}, ())

    ids: list[str] = []
    subject = plain("subject_key", "subject_key_ct")

    def write(channels: list[str], purposes: list[str], outcome: str, cause: str | None = None) -> None:
        ev = record_tenant_event(
            conn, crypto, contact=norm, contact_kind=grant["contact_kind"], event_type="release", channels=channels,
            purposes=purposes, method=grant["method"], origin="consumer", disclosure_sha256=grant["disclosure_sha256"],
            subject_key=subject, captured_at=grant["captured_at"], session_ref=session, source=RELEASE_SOURCE,
            source_id=grant["source_id"], brand_ids=grant["brand_ids"] or (), recorded_by=RELEASER,
            release_of_event_id=gid, release_outcome=outcome, release_cause=cause)
        ids.append(ev.event_id)

    if released:
        write(released, released_purposes, "released")
    for cause in sorted(refused):
        write(refused[cause], list(grant["purposes"]), "refused", cause)
    return ReleaseResult(tuple(released), {c: tuple(v) for c, v in refused.items()}, tuple(ids))
