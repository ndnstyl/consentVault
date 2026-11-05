"""The one door (specs/capture-everything/one-door.md).

The product is an append-only record of what was sent. Every entry point (the HTTP servers, the text reply, the command line,
the library, a connector) is a thin adapter that does two things and nothing else:

1. ``store_raw``: hand the request, whole, to the raw post store. It parses nothing and decides nothing.
2. ``project_post``: ask the projection to append the event that post produces, if it produces one.

Between them sits one pure reader and one pure rule set, neither touching a database, a clock or the network:

* ``read_post(bytes, field_map, code_version)``: what the stored bytes say (a consent or a stop, or a text, or nothing readable).
* ``decide``: the fold rule for one post given the facts stored beside it and the request keys earlier posts already produced
  events from. A text never creates consent. A stop always counts. A duplicate (the same signed request) counts once.

The events are a rebuildable projection of the posts with one writer (this module). Each event cites the one post it came from
and the database refuses a second event for the same post or the same signed request, so running the projection again is always
safe and a crash means run it again (``rebuild``). No claim, no seen-request record and no transaction choreography decides
anything at intake.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping

import psycopg

from . import edge_envelope, rawpost, safelog
from .errors import (ConsentVaultError, EmptyConsentError, InvalidEventError, UncheckedConsentError)
from .ledger import Event, record_event
from .rawpost import Fact, RawPostWriter, RawRequest, StoredPost

_log = safelog.get("consentvault.door")

CODE_VERSION = "door-1"
REASON_TEXT = "a_text_is_not_consent"
EDGE_INTAKES = ("edge_single", "edge_site_key")

EVENT_FIELDS = (
    "contact", "event_type", "channels", "purposes", "method", "origin", "disclosure_sha256",
    "subject_key", "captured_at", "page_url", "client_ip", "user_agent", "session_ref",
    "bot_check", "source", "recorded_by", "edge_received_at", "payload_sha256", "contact_verification", "contact_kind",
)
CAPTURE_KEYS = frozenset({
    "contact", "event_type", "channels", "purposes", "method", "origin", "disclosure_sha256", "subject_key", "captured_at",
    "page_url", "client_ip", "user_agent", "session_ref", "bot_check", "source", "edge_received_at", "contact_verification",
    "checked", "inbound_message", "source_id", "brand_ids", "attribution", "display"})
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


# ---- the pure reader ---------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Reading:
    """What the bytes of one post say. ``kind`` is ``event`` (the fields of one event are in ``payload``), ``text`` (an inbound
    text: stored, never consent) or ``unreadable`` (``reason`` says why nothing can follow)."""

    code_version: str
    kind: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    reason: str | None = None
    body_sha256: str = ""


def read_post(body: bytes, field_map: Any = None, code_version: str = CODE_VERSION, *, intake: str = "api_single",
              context: Mapping[str, Any] | None = None) -> Reading:
    """The one reader. Pure: the same bytes, field map, code version and context always give the same reading. ``context`` is
    what the intake knew about the sender when it stored the post (``tenant``, ``source_id``, ``brand_ids``), kept beside the
    post as facts."""
    ctx = dict(context or {})
    sha = hashlib.sha256(body).hexdigest()
    try:
        if intake in EDGE_INTAKES:
            env = edge_envelope.unpack(body)
            inner = env.body
        else:
            env, inner = None, body
        payload = json.loads(inner.decode("utf-8"))
    except edge_envelope.EnvelopeUnreadable:  # loud-failure-exempt: the reading says edge_envelope_unreadable; the signed bytes stay stored
        return Reading(code_version, "unreadable", reason="edge_envelope_unreadable", body_sha256=sha)
    except (ValueError, UnicodeDecodeError):  # loud-failure-exempt: the reading says not_json; the bytes stay stored
        return Reading(code_version, "unreadable", reason="not_json", body_sha256=sha)
    if not isinstance(payload, dict):
        return Reading(code_version, "unreadable", reason="not_a_json_object", body_sha256=sha)
    tenant = bool(ctx.get("tenant"))
    if (env.method if env is not None else ctx.get("method", "POST")).upper() != "POST" or (
            env is None and ctx.get("path", "/v1/events") != "/v1/events"):
        return Reading(code_version, "unreadable", reason="not_an_event_post", body_sha256=sha)
    if env is not None:
        owner = ctx.get("owner") or {}
        payload = edge_envelope.widget_event(
            payload, env.headers, env.edge_facts, source_id=owner.get("source_id") if tenant else None,
            brand_ids=owner.get("brand_ids") if tenant else None, source="site_key" if tenant else None)
        if not tenant:
            payload.pop("source_id", None)
            payload.pop("brand_ids", None)
            payload["payload_sha256"] = hashlib.sha256(inner).hexdigest()
    elif tenant:
        payload = {k: v for k, v in payload.items() if k in CAPTURE_KEYS}
    else:
        payload = {k: payload[k] for k in (*EVENT_FIELDS, "checked", "inbound_message") if k in payload}
    if payload.get("event_type") == "grant" and (
            payload.get("contact_verification") == "inbound_keyword" or "inbound_message" in payload):
        return Reading(code_version, "text", reason=REASON_TEXT, body_sha256=sha)
    return Reading(code_version, "event", payload, body_sha256=sha)


# ---- the pure rule set --------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Auth:
    """What the intake established about the sender, read from the facts stored beside the post."""

    reason: str | None = None       # why this post cannot produce an event (not_authenticated:<why>, replay, stale_timestamp ...)
    key: str | None = None          # the request's own identity (its signature, the edge's request id, a request id header)
    verified_key: bool = False      # the verified-grant secret signed it (or a local caller the vault trusts)


def auth_from_facts(facts: Mapping[tuple[str, str], Any]) -> Auth:
    """Read the sender's standing from the facts. Pure."""
    def vault(name, default=None):
        return facts.get(("vault", name), default)

    key = vault("request_key")
    verified = vault("authenticated_by") in ("verified_key", "local")
    cred = vault("credential")
    if vault("request_signature") not in (None, "valid"):
        return Auth("not_authenticated:" + str(vault("request_signature")), key, verified)
    if vault("tenant") is True:
        if vault("edge_timestamp") == "stale":
            return Auth("stale_timestamp", key, verified)
        if vault("replay", "fresh") != "fresh":
            return Auth("replay", key, verified)
        if not (isinstance(cred, dict) and cred.get("state") == "verified"):
            return Auth("no_credential", key, verified)
        return Auth(None, key, verified)
    if vault("request_signature") is None:
        return Auth("not_authenticated:unsigned", key, verified)
    if vault("replay", "fresh") != "fresh":
        return Auth("replay", key, verified)
    return Auth(None, key, verified)


def decide(reading: Reading, auth: Auth, seen_keys: Callable[[str], bool] | set) -> str | None:
    """The fold rule for one post: None when it produces one event, else the plain reason it produces none. Pure."""
    if auth.reason:
        return auth.reason
    if reading.kind != "event":
        return reading.reason or REASON_TEXT
    seen = seen_keys if callable(seen_keys) else seen_keys.__contains__
    if auth.key and seen(auth.key):
        return "request_seen_before"
    return None


# ---- the single-company backend: typed fields and the ledger's one append ------------------------------------------------

def _list(value: Any) -> list[str]:
    return [value] if isinstance(value, str) else [c for c in (value or []) if c]


class SingleBackend:
    """Writes the event of one post into the single-company chain, with the capture rules: a grant needs the box checked, a
    channel, a purpose and the wording hash; a verified grant needs the integrator's key; a stop always records."""

    def __init__(self, region: str | None = None, allowed_purposes=None) -> None:
        self.region, self.allowed_purposes = region, allowed_purposes

    def prepare(self, conn, payload: Mapping[str, Any], body: bytes, auth: Auth) -> dict | str:
        """The typed fields of the event, or the plain reason this post produces none."""
        fields = {k: payload[k] for k in EVENT_FIELDS if k in payload}
        if fields.get("event_type") != "grant":
            fields.pop("contact_verification", None)
        for required in ("contact", "event_type", "channels", "purposes"):
            if required not in fields:
                return f"missing_field:{required}"
        if fields.get("contact_verification", "none") != "none" and not auth.verified_key:
            return "verification_key_required"
        fields.setdefault("method", "checkbox")
        fields.setdefault("origin", "consumer")
        for name in ("captured_at", "edge_received_at"):
            if fields.get(name) is not None:
                try:
                    fields[name] = datetime.fromisoformat(str(fields[name]).replace("Z", "+00:00"))
                except ValueError:  # loud-failure-exempt: returned as the stored reason bad_<field>
                    return f"bad_{name}"
        if fields.get("payload_sha256") is not None and not _SHA256_HEX.match(str(fields["payload_sha256"])):
            fields.pop("payload_sha256")
        fields.setdefault("payload_sha256", hashlib.sha256(body).hexdigest())
        fields["region"] = self.region
        fields["allowed_purposes"] = self.allowed_purposes
        if fields["event_type"] == "grant":
            verification = fields.get("contact_verification", "none")
            if verification not in ("none", "otp"):
                raise InvalidEventError("verification must be 'otp'")
            if verification == "otp" and "checked" not in payload:
                raise InvalidEventError(
                    "a verified grant needs the consent box value the person sent (checked); it is never defaulted")
            if payload.get("checked") is not True:
                raise UncheckedConsentError("the consent box was not checked; no grant recorded")
            chans, purps = _list(fields["channels"]), _list(fields["purposes"])
            if not chans or not purps:
                raise EmptyConsentError("a grant must name at least one channel and one purpose")
            if not fields.get("disclosure_sha256"):
                raise EmptyConsentError("a grant must carry the hash of the disclosure the person saw")
            fields["channels"], fields["purposes"] = chans, purps
        return fields

    def apply(self, conn, fields: dict) -> Event:
        return record_event(conn, **fields)


# ---- the door ------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class PostView:
    """One stored post as the projection reads it: the bytes, the facts beside it, where it sits in the order."""

    org_id: str
    post_id: str
    seq: int
    intake: str
    body: bytes
    facts: Mapping[tuple[str, str], Any]
    method: str = "POST"
    path: str = "/v1/events"


@dataclass(frozen=True)
class Outcome:
    """What the projection did for one post: an event, or the plain reason it produced none."""

    post_id: str
    event: Event | None = None
    reason: str | None = None


def store_raw(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, req: RawRequest) -> StoredPost:
    """The one thing an entry point calls to take a request in: the whole request is stored first. Parses nothing."""
    return writer.write(conn, enter, req)


def _context(facts: Mapping[tuple[str, str], Any]) -> dict:
    return {"tenant": facts.get(("vault", "tenant")) is True, "owner": facts.get(("vault", "site_owner"))}


def _view_context(view: "PostView") -> dict:
    return {**_context(view.facts), "method": view.method, "path": view.path}


def _ctx(conn, enter):
    return enter(conn) if enter is not None else conn.transaction()


def _seen(conn, org: str) -> Callable[[str], bool]:
    def seen(key: str) -> bool:
        return conn.execute("SELECT 1 FROM consentvault.event_source_post WHERE org_id = %s AND request_key = %s"
                            " AND role = 'trigger'", (uuid.UUID(org), key)).fetchone() is not None
    return seen


def project_view(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, backend: Any, view: PostView, *,
                 field_map: Any = None, raise_errors: bool = False) -> Outcome:
    """Append the event one post produces, if it produces one, and record the plain reason when it does not. Idempotent: a post
    already projected, or a request already counted, appends nothing. Never judges the sender. A caller in this process
    (``raise_errors``) is also given the error that names why no event was written, after the reason is stored."""
    reading = read_post(view.body, field_map, CODE_VERSION, intake=view.intake, context=_view_context(view))
    auth = auth_from_facts(view.facts)
    try:
        with _ctx(conn, enter):
            reason = decide(reading, auth, _seen(conn, view.org_id))
            fields = backend.prepare(conn, reading.payload, view.body, auth) if reason is None else None
            if reason is not None or isinstance(fields, str):
                outcome = Outcome(view.post_id, reason=reason or fields)
            else:
                try:
                    event = backend.apply(conn, fields)
                    conn.execute(
                        "INSERT INTO consentvault.event_source_post (org_id, event_id, post_id, role, request_key)"
                        " VALUES (%s, %s, %s, 'trigger', %s)",
                        (uuid.UUID(view.org_id), uuid.UUID(event.event_id), uuid.UUID(view.post_id), auth.key))
                except psycopg.errors.UniqueViolation:
                    raise _AlreadyProjected() from None
                outcome = Outcome(view.post_id, event=event)
    except _AlreadyProjected:
        outcome = Outcome(view.post_id, reason="request_seen_before")
    except ConsentVaultError as exc:
        _record(writer, conn, enter, view, Outcome(view.post_id, reason=type(exc).__name__))
        if raise_errors:
            raise
        return Outcome(view.post_id, reason=type(exc).__name__)
    except psycopg.Error as exc:
        _log.error("the event of a stored post could not be written; the projection will run again for it",
                   error=type(exc).__name__)
        if raise_errors:
            raise
        return Outcome(view.post_id, reason="unavailable:" + type(exc).__name__)
    _record(writer, conn, enter, view, outcome)
    if raise_errors and outcome.event is None:
        if outcome.reason == REASON_TEXT:
            raise InvalidEventError("a START text restores nothing; the way back is a form (verification 'otp' or none)")
        raise InvalidEventError(f"the post is stored and no event was written: {outcome.reason}")
    return outcome


class _AlreadyProjected(Exception):
    pass


def _record(writer, conn, enter, view: PostView, outcome: Outcome) -> Outcome:
    """Leave the plain outcome beside the post as a fact (appended; the post is never touched)."""
    try:
        if outcome.event is None and (outcome.reason or "").startswith("unavailable:"):
            return outcome
        fact = Fact("vault", "event_derived", outcome.event.event_id) if outcome.event is not None else \
            Fact("vault", "event_not_derived", outcome.reason)
        writer.append_facts(conn, enter, view.org_id, view.post_id, view.facts.get(("__key__", "data_key")), [fact])
    except (ConsentVaultError, psycopg.Error) as exc:
        _log.error("the outcome of a stored post could not be recorded beside it", error=type(exc).__name__)
    return outcome


def project_post(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, backend: Any, view: PostView, *,
                 field_map: Any = None, raise_errors: bool = False) -> Outcome:
    """Project one post just stored. A vault that can read its own posts first brings every earlier post that has no outcome up
    to date, in arrival order, so a crash before this call never changes which of two copies of one request counts."""
    if view.facts.get(("__can_read__", "catch_up")) is True:
        project_pending(writer, conn, enter, backend, through_seq=view.seq - 1)
    return project_view(writer, conn, enter, backend, view, field_map=field_map, raise_errors=raise_errors)


def read_view(writer: RawPostWriter, conn: psycopg.Connection, org: str, post_id: str, seq: int, intake: str,
              method: str = "POST", path: str = "/v1/events") -> PostView:
    data_key = writer.open_key(conn, uuid.UUID(org), post_id)
    return PostView(org, post_id, seq, intake, writer.read_body(conn, uuid.UUID(org), post_id),
                    {**writer.read_facts(conn, uuid.UUID(org), post_id), ("__key__", "data_key"): data_key}, method, path)


def project_pending(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, backend: Any, *,
                    through_seq: int | None = None) -> list[Outcome]:
    """Run the projection for every stored post that has no outcome yet, in arrival order. Safe to run any number of times."""
    with _ctx(conn, enter):
        rows = conn.execute(
            "SELECT p.org_id::text AS org, p.post_id::text AS post_id, p.seq, p.intake, p.method, p.path FROM consentvault.raw_post p"
            " WHERE p.org_id = (SELECT consentvault.current_org()) AND p.kind = 'post'"
            "   AND (%s::bigint IS NULL OR p.seq <= %s)"
            "   AND NOT EXISTS (SELECT 1 FROM consentvault.event_source_post s WHERE s.org_id = p.org_id"
            "                   AND s.post_id = p.post_id AND s.role = 'trigger')"
            "   AND NOT EXISTS (SELECT 1 FROM consentvault.raw_post_fact f WHERE f.org_id = p.org_id"
            "                   AND f.post_id = p.post_id AND f.name = 'event_not_derived')"
            " ORDER BY p.seq", (through_seq, through_seq)).fetchall()
        views = [read_view(writer, conn, r["org"], r["post_id"], r["seq"], r["intake"], r["method"], r["path"]) for r in rows]
    return [project_view(writer, conn, enter, backend, v) for v in views]


def rebuild(conn: psycopg.Connection, *, backend: Any = None, writer: RawPostWriter | None = None,
            enter: Callable | None = None) -> list[Outcome]:
    """Run the projection again over everything stored. A crash between a post's answer and its event is repaired by this and
    nothing else; running it twice changes nothing."""
    return project_pending(writer or RawPostWriter(), conn, enter, backend or SingleBackend())


# ---- the library and command line adapters' way in -----------------------------------------------------------------------

def submit(conn: psycopg.Connection, *, intake: str, payload: Mapping[str, Any], region: str | None = None,
           allowed_purposes=None, verified: bool = True, writer: RawPostWriter | None = None) -> Event:
    """A caller in this process (the library, the command line) hands its request to the door. The request is stored whole as
    JSON, then projected; the event is returned, or the error that names why none was written is raised, after the post is
    stored either way."""
    def default(v):
        if isinstance(v, datetime):
            return v.isoformat()
        raise TypeError(f"{type(v).__name__} is not JSON")

    writer = writer or RawPostWriter()
    body = json.dumps(dict(payload), default=default, sort_keys=True).encode("utf-8")
    facts = (Fact("vault", "request_signature", "valid"), Fact("vault", "replay", "fresh"),
             Fact("vault", "authenticated_by", "local" if verified else "shared_secret"))
    req = RawRequest(intake=intake, method="POST", path="/v1/events", query="", headers=(("content-type", "application/json"),),
                     body=body, headers_presented_by="local-process", facts=facts)
    stored = store_raw(writer, conn, None, req)
    all_facts = {("vault", f.name): f.value for f in facts}
    all_facts[("__can_read__", "catch_up")] = True
    all_facts[("__key__", "data_key")] = stored.data_key
    view = PostView(stored.org_id, stored.post_id, stored.seq, intake, body, all_facts)
    return project_post(writer, conn, None, SingleBackend(region, allowed_purposes), view, raise_errors=True).event
