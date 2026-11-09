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

import base64
import contextlib
import functools
import hashlib
import json
import re
import urllib.parse
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

import psycopg

from . import edge_envelope, safelog, stopwords
from .errors import (ClockSkewError, ConsentVaultError, EmptyConsentError, InvalidEventError, UncheckedConsentError)
from . import ledger
from .ledger import Event, record_event, record_tenant_event
from .normalize import normalize_contact
from .rawpost import Fact, RawPostWriter, RawRequest, StoredPost, request_key_digest

_log = safelog.get("consentvault.door")

CODE_VERSION = "door-2"
REASON_TEXT = "a_text_is_not_consent"
EDGE_INTAKES = ("edge_single", "edge_site_key")
TENANT_SETTINGS_FACT = "tenant_projection_settings"
WORDING_FACT = "wording_known_at_arrival"

EVENT_FIELDS = (
    "contact", "event_type", "channels", "purposes", "method", "origin", "disclosure_sha256",
    "subject_key", "captured_at", "page_url", "client_ip", "user_agent", "session_ref",
    "bot_check", "source", "recorded_by", "edge_received_at", "payload_sha256", "contact_verification", "contact_kind",
)
CAPTURE_KEYS = frozenset({
    "contact", "event_type", "channels", "purposes", "method", "origin", "disclosure_sha256", "subject_key", "captured_at",
    "page_url", "client_ip", "user_agent", "session_ref", "bot_check", "source", "edge_received_at", "contact_verification",
    "checked", "inbound_message", "source_id", "brand_ids", "attribution", "display"})
PROVIDER_INTAKES = ("sms_reply",)
SYSTEM_INTAKES = ("system_stop", "signal", "stop_page", "restore", "erasure", "provider_refusal", "staff_marked")
SYSTEM_FIELDS = (*EVENT_FIELDS, "source_id", "brand_ids", "attribution", "source_system_id", "payload_b64")
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
    if intake == "sms_reply":
        return _read_text_reply(body, code_version, sha)
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
    if intake in SYSTEM_INTAKES:
        return Reading(code_version, "event", {k: payload[k] for k in SYSTEM_FIELDS if k in payload}, body_sha256=sha)
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


def _read_text_reply(body: bytes, code_version: str, sha: str) -> Reading:
    """A reply the text provider posted (a form body). A whole stop word is a stop and always counts; any other text, START
    included, is stored as received and creates nothing."""
    try:
        params = dict(urllib.parse.parse_qsl(body.decode("utf-8"), keep_blank_values=True))
    except UnicodeError:  # loud-failure-exempt: the reading says not_a_form; the bytes stay stored
        return Reading(code_version, "unreadable", reason="not_a_form", body_sha256=sha)
    sender, text = params.get("From", ""), params.get("Body", "")
    if not sender or "MessageStatus" in params:
        return Reading(code_version, "unreadable", reason="not_a_reply", body_sha256=sha)
    action = stopwords.read_text(text)[2]
    if action != "stop":
        return Reading(code_version, "text", reason=REASON_TEXT if action == "start" else "not_a_stop", body_sha256=sha)
    return Reading(code_version, "event", {"contact": sender, "event_type": "revoke", "purposes": ["*"], "method": "keyword",
                                           "origin": "consumer", "session_ref": f"twilio:{params.get('MessageSid', '')}"[:200]},
                   body_sha256=sha)


# ---- the pure rule set --------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Auth:
    """What the intake established about the sender, read from the facts stored beside the post."""

    reason: str | None = None       # why this post cannot produce an event (not_authenticated:<why>, stale_timestamp ...)
    soft: bool = False              # the reason is a fact about age or a lookup outage: a stop is counted anyway
    pending: bool = False           # the intake could not finish its lookup: the post waits, it is neither refused nor counted
    key: str | None = None          # the request's own identity (its signature, the edge's request id, a request id header)
    verified_key: bool = False      # the verified-grant secret signed it (or a local caller the vault trusts)
    org_id: str = ""
    credential: Mapping[str, Any] | None = None   # the verified credential a multi-tenant intake established (id, scopes)


def auth_from_facts(facts: Mapping[tuple[str, str], Any]) -> Auth:
    """Read the sender's standing from the facts. Pure."""
    def vault(name, default=None):
        return facts.get(("vault", name), default)

    raw_key = vault("request_key")
    key = request_key_digest(raw_key) if isinstance(raw_key, str) and raw_key else None
    verified = vault("authenticated_by") in ("verified_key", "local")
    cred = vault("credential")
    cred = cred if isinstance(cred, dict) and cred.get("state") == "verified" else None

    def auth(reason, soft=False, pending=False):
        return Auth(reason, key=key, verified_key=verified, credential=cred, soft=soft, pending=pending)

    sig = vault("request_signature")
    if sig not in (None, "valid"):
        return auth("not_authenticated:" + str(sig), soft=str(sig) == "stale_timestamp" or str(sig).startswith("clock_unavailable:"))
    if vault("tenant") is True:
        if vault("edge_timestamp") == "stale":
            return auth("stale_timestamp", soft=True)
        if cred is None and str(vault("site_key_lookup", "")).startswith("failed:"):
            return auth("site_key_lookup_failed", pending=True)
        return auth(None if cred is not None else "no_credential")
    if sig is None:
        return auth("not_authenticated:unsigned")
    return auth(None)


def decide(reading: Reading, auth: Auth, seen_keys: Callable[[str], bool] | set) -> str | None:
    """The fold rule for one post: None when it produces one event, else the plain reason it produces none. Pure."""
    stop = reading.kind == "event" and reading.payload.get("event_type") in ("revoke", "suppress")
    if auth.reason and not (auth.soft and stop):
        return auth.reason
    if reading.kind != "event":
        return reading.reason or REASON_TEXT
    seen = seen_keys if callable(seen_keys) else seen_keys.__contains__
    if auth.key and seen(auth.key):
        return "request_seen_before"
    return None


class Backends:
    """The writers one process owns, by intake. The projection of a post uses the writer of its intake; a post of an intake this
    process has no writer for is left for the process that has one (it is never refused and never recorded as not derived)."""

    def __init__(self, by_intake: Mapping[str, Any]) -> None:
        self.by_intake = dict(by_intake)

    def get(self, intake: str) -> Any:
        return self.by_intake.get(intake) or self.by_intake.get("*")


PROJECTION_ROLE = "consentvault_projection"


def _restricted(backend: Any) -> bool:
    """True when every writer this process projects with works in an organisation's chain, where the projection must run under the
    role that cannot read the configuration tables (migration 0093)."""
    if isinstance(backend, Backends):
        return bool(backend.by_intake) and all(getattr(b, "restricted_login", False) for b in backend.by_intake.values())
    return bool(getattr(backend, "restricted_login", False))


def _under_projection_login(fn):
    """The cloud's projection must run on the projection login (a member of ``consentvault_projection`` and not of the app group,
    migration 0093): that role cannot read the configuration tables, so a read of live configuration anywhere in the projection,
    however it is written, raises ``permission denied`` and is an attempt. The login is the connection's own, so there is no role
    to switch back from. A connection that is not that login is a misconfiguration and raises before anything is projected."""
    @functools.wraps(fn)
    def wrapper(writer, conn, enter, backend, *args, **kwargs):
        if _restricted(backend):
            row = conn.execute("SELECT pg_has_role(current_user, %s, 'MEMBER') AS projection,"
                               " pg_has_role(current_user, 'consentvault_app', 'MEMBER') AS app", (PROJECTION_ROLE,)).fetchone()
            if not row["projection"] or row["app"]:
                raise ConsentVaultError("the projection must run on the projection login (a member of consentvault_projection and "
                                        "not of consentvault_app); this connection is not that login")
        return fn(writer, conn, enter, backend, *args, **kwargs)
    return wrapper


def _backend_for(backend: Any, intake: str) -> Any:
    return backend.get(intake) if isinstance(backend, Backends) else backend


def settings_fact(*, region: str | None = None, allowed_purposes=None, defaults: Mapping[str, Any] | None = None) -> Fact:
    """The settings a post is projected with, stored beside the post when it is taken in: whichever process projects it later
    (the server, the rebuild job, the command line) reads these and never its own."""
    return Fact("vault", "projection_settings", {
        "region": region, "allowed_purposes": sorted(allowed_purposes) if allowed_purposes is not None else None,
        "defaults": {k: str(v) if isinstance(v, uuid.UUID) else v for k, v in (defaults or {}).items()}})


def _stored_settings(facts: Mapping[tuple[str, str], Any]) -> dict | None:
    value = facts.get(("vault", "projection_settings"))
    return value if isinstance(value, dict) else None


# ---- the single-company backend: typed fields and the ledger's one append ------------------------------------------------

def _list(value: Any) -> list[str]:
    return [value] if isinstance(value, str) else [c for c in (value or []) if c]


class SingleBackend:
    """Writes the event of one post into the single-company chain, with the capture rules: a grant needs the box checked, a
    channel, a purpose and the wording hash; a verified grant needs the integrator's key; a stop always records."""

    takes_arrival = True   # the ledger compares the claimed capture time against the post's stored arrival, not the clock at projection

    def __init__(self, region: str | None = None, allowed_purposes=None) -> None:
        self.region, self.allowed_purposes = region, allowed_purposes

    def for_post(self, facts: Mapping[tuple[str, str], Any]) -> "SingleBackend":
        stored = _stored_settings(facts)
        if stored is None:
            return self
        return SingleBackend(stored.get("region"), stored.get("allowed_purposes"))

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
        normalize_contact(fields["contact"], fields.get("contact_kind"), self.region)   # raises NormalizationError: the contact reads the same every time
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

    def apply(self, conn, enter, fields: dict, link: Callable) -> str:
        """Append the event and the link to its post in one transaction; returns the event id."""
        with conn.transaction():
            event = record_event(conn, **fields)
            link(conn, event.event_id)
        return event.event_id


class TenantBackend:
    """Writes the event of one post into the entered organisation's chain through the capture pipeline (evidence object, receipt,
    the tenant's own checks). The pipeline puts the link in the transaction that writes the event."""

    takes_arrival = True

    def __init__(self, pipeline: Any, enter_for_credential: Callable[[str, Mapping[str, Any]], Callable],
                 settings: Mapping[str, Any] | None = None, wording: Mapping[str, Any] | None = None,
                 restricted_login: bool = False) -> None:
        self.pipeline, self.enter_for_credential, self.settings, self.wording = pipeline, enter_for_credential, settings, wording
        self.restricted_login = restricted_login   # True only for the cloud's projection, which runs on the projection login

    def for_post(self, facts: Mapping[tuple[str, str], Any]) -> "TenantBackend":
        """The projection of a post reads the organisation's configuration as it stood when the post arrived (stored beside it
        by the intake), never the live configuration. A post stored before the intake kept this reads the live one."""
        stored = facts.get(("vault", TENANT_SETTINGS_FACT))
        wording = facts.get(("vault", WORDING_FACT))
        return TenantBackend(self.pipeline, self.enter_for_credential, stored if isinstance(stored, dict) else None,
                             wording if isinstance(wording, dict) else None, restricted_login=self.restricted_login)

    def prepare(self, conn, payload: Mapping[str, Any], body: bytes, auth: Auth) -> dict | str:
        from .tenancy.admin_base import ApiError
        from .tenancy.pipeline import check_channel_purpose, check_source_from_settings, parse_capture, settings_complete, stop_settings
        from .tenancy.pipeline import check_wording_from_fact
        from .tenancy.pipeline import normalize as normalize_tenant_contact

        cred = auth.credential or {}
        settings = self.settings
        if not settings_complete(settings):
            if payload.get("event_type") not in ("revoke", "suppress"):
                return "settings_missing_at_arrival"   # final for a grant: never decided from the live configuration
            settings = stop_settings(payload)          # a stop is decided from the post alone, never lost for want of configuration
        try:
            req = parse_capture(dict(payload), body, tuple(cred.get("scopes") or ()))
            f = dict(req.fields)
            # decided only from what was stored beside the post at arrival (or the post alone, for a stop): final
            check_channel_purpose(f["channels"], f["purposes"], allow_star=f["event_type"] != "grant", stored=settings)
            check_source_from_settings(f, settings)
            normalize_tenant_contact(f["contact"], settings["region"])   # an unreadable contact reads the same every time: final
            check_wording_from_fact(f, self.wording)   # the wording as the intake saw it, stored at arrival: final
            check_event_shape(f)   # the box, the channel, the purpose, the wording hash: the bytes alone, final
        except ApiError as exc:
            return exc.name
        return {"req": req, "credential_id": uuid.UUID(str(cred.get("credential_id"))), "credential": dict(cred), "org_id": auth.org_id,
                "settings": settings, "wording": self.wording}

    def reroute(self, writer, conn, view: "PostView", owner, found: Mapping[tuple[str, str], Any]):
        """Store the post again in the organisation the site key belongs to, with everything known about it (the original facts,
        the repeated lookup's answer, and where it was first stored); returns the new post's view and the entry to use for it."""
        cred = {"credential_id": str(owner.credential_id), "scopes": ["capture"]}
        enter = self.enter_for_credential(str(owner.org_id), cred)
        facts = {k: v for k, v in view.facts.items() if k[0] != "__key__"}
        facts.update(found)
        facts[("vault", "stored_again_from")] = {"org_id": view.org_id, "post_id": view.post_id}
        req = RawRequest(intake=view.intake, method=view.method, path=view.path, query="",
                         headers=(("content-type", "application/json"),), body=view.body, headers_presented_by="rebuild",
                         facts=tuple(Fact(s, n, v) for (s, n), v in facts.items()),
                         original_arrival=datetime.fromtimestamp(view.arrived_epoch, tz=timezone.utc) if view.arrived_epoch is not None else None)
        stored = writer.write(conn, enter, req)
        newview = PostView(stored.org_id, stored.post_id, stored.seq, view.intake, view.body,
                           {**facts, ("__key__", "data_key"): stored.data_key}, view.method, view.path,
                           stored.received_at.timestamp())
        return newview, enter

    def apply(self, conn, enter, fields: dict, link: Callable) -> str:
        result = self.pipeline.capture(conn, self.enter_for_credential(fields["org_id"], fields["credential"]), fields["req"], credential_id=fields["credential_id"],
                                       link=link, settings=fields.get("settings"), arrived_at=fields.get("arrived_at"),
                                       wording=fields.get("wording"))
        return result.event_id


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
    arrived_epoch: float | None = None   # when the post arrived (the database's clock at intake), as seconds since the epoch


@dataclass(frozen=True)
class Outcome:
    """What the projection did for one post: the event it appended, or the plain reason it produced none."""

    post_id: str
    event_id: str | None = None
    reason: str | None = None
    retry: bool = False   # unfinished: an error stopped the post, nothing was stored as final, and the next projection repeats it
    halts: bool = False   # unfinished: no later post is projected before this one until the halt bound passes, so arrival order holds


WAITING = "waiting_for_an_earlier_post"
WAITING_TO_RETRY = "waiting_for_its_next_attempt"


@dataclass(frozen=True)
class StoredWaiting:
    """The library's and the command line's answer when the post is stored whole and an earlier stored post is unfinished: this
    post is projected after it, in arrival order, by the next run. It is neither an event nor an invalid request."""

    post_id: str
    seq: int
    stored: bool = True
    waiting: bool = True
    reason: str = WAITING

    def as_dict(self) -> dict:
        return {"stored": self.stored, "waiting": self.waiting, "post_id": self.post_id, "seq": self.seq, "reason": self.reason}


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
        return conn.execute("SELECT consentvault.request_counted(%s) AS counted", (key,)).fetchone()["counted"]
    return seen


def reason_of(exc: BaseException) -> str:
    """The plain name an error goes by: the contract name of an API error, the class of a vault error, the class of a database
    fault behind a ledger error, else the error's own class. Never the text."""
    from .errors import LedgerError
    from .tenancy.admin_base import ApiError

    if isinstance(exc, ApiError):
        return exc.name
    if isinstance(exc, LedgerError):
        return "LedgerError:" + type(exc.__cause__).__name__ if exc.__cause__ is not None else "LedgerError"
    if isinstance(exc, ConsentVaultError):
        return type(exc).__name__
    return type(exc).__name__


def _is_uuid(value: Any) -> bool:
    try:
        uuid.UUID(str(value))
    except ValueError:  # loud-failure-exempt: a malformed id is stored as that post's reason by the caller
        return False
    return True


@_under_projection_login
def project_view(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, backend: Any, view: PostView, *,
                 field_map: Any = None, raise_errors: bool = False) -> Outcome:
    """Append the event one post produces, if it produces one, and record the plain reason when it does not. Idempotent: a post
    already projected, or a request already counted, appends nothing. Never judges the sender. A caller in this process
    (``raise_errors``) is also given the error that names why no event was written, after the reason is stored."""
    backend = _backend_for(backend, view.intake)
    if backend is None:
        return Outcome(view.post_id, reason="no_writer_for_intake")
    if view.intake in PROVIDER_INTAKES and view.facts.get(("vault", "request_signature")) is None:
        return Outcome(view.post_id, reason="awaiting_authentication")   # not yet judged by its intake: neither refused nor counted
    org = uuid.UUID(view.org_id) if _is_uuid(view.org_id) else None

    try:
        try:
            base_backend = backend
            if hasattr(backend, "for_post"):
                backend = backend.for_post(view.facts)
            reading = read_post(view.body, field_map, CODE_VERSION, intake=view.intake, context=_view_context(view))
            auth = replace(auth_from_facts(view.facts), org_id=view.org_id)
            if auth.pending:
                moved = _resolve_site_key(writer, conn, enter, backend, view, field_map=field_map, raise_errors=raise_errors)
                if isinstance(moved, Outcome):
                    return moved
                view = moved
                if hasattr(base_backend, "for_post"):   # the repeated lookup stored the settings beside the post: read them now
                    backend = base_backend.for_post(view.facts)
                reading = read_post(view.body, field_map, CODE_VERSION, intake=view.intake, context=_view_context(view))
                auth = replace(auth_from_facts(view.facts), org_id=view.org_id)

            def link(c, event_id):
                c.execute("INSERT INTO consentvault.event_source_post (org_id, event_id, post_id, role, request_key)"
                          " VALUES (%s, %s, %s, 'trigger', %s)", (org, uuid.UUID(str(event_id)), uuid.UUID(view.post_id), auth.key))

            with _ctx(conn, enter):
                reason = decide(reading, auth, _seen(conn, view.org_id))
            try:
                fields = backend.prepare(conn, reading.payload, view.body, auth) if reason is None else None
            except (MemoryError, RecursionError, psycopg.Error):   # the machine or the database, not the bytes: an attempt below, never a final reason
                raise
            except Exception as exc:  # loud-failure-exempt: the pure phase of the reader; its refusal is final and is stored below
                _log.error("a stored post produces no event; the reason is stored beside it", error=reason_of(exc))
                _record(writer, conn, enter, view, Outcome(view.post_id, reason=reason_of(exc)))
                raise _FinalReading from exc
            if isinstance(fields, dict) and getattr(backend, "takes_arrival", False) and view.arrived_epoch is not None:
                fields["arrived_at"] = datetime.fromtimestamp(view.arrived_epoch, tz=timezone.utc)
                claimed = fields.get("captured_at", getattr(fields.get("req"), "fields", {}).get("captured_at"))
                if isinstance(claimed, datetime) and claimed.tzinfo is not None and claimed > fields["arrived_at"] + ledger.MAX_CAPTURE_SKEW:
                    skew = ClockSkewError("the claimed capture time is later than the post's arrival plus the skew bound")
                    _log.error("a stored post produces no event; the reason is stored beside it", error=reason_of(skew))
                    _record(writer, conn, enter, view, Outcome(view.post_id, reason=reason_of(skew)))
                    raise _FinalReading from skew
            if reason is not None or isinstance(fields, str):
                outcome = Outcome(view.post_id, reason=reason or fields)
            else:
                try:
                    outcome = Outcome(view.post_id, event_id=backend.apply(conn, enter, fields, link))
                except psycopg.errors.UniqueViolation:
                    raise _AlreadyProjected() from None
        except _AlreadyProjected:
            outcome = _already(conn, enter, view)
            if outcome.event_id is not None:
                return outcome
    except _FinalReading as final:
        if raise_errors:
            raise final.__cause__
        return Outcome(view.post_id, reason=reason_of(final.__cause__))
    except Exception as exc:  # loud-failure-exempt: no error is final; it is logged, handed on, and the post is projected again on the next run
        reason = reason_of(exc)
        _log.error("the event of a stored post could not be written; the projection will run again for it", error=reason)
        _attempt(conn, enter, view.org_id, view.post_id, reason)
        if raise_errors:
            raise
        return Outcome(view.post_id, reason=reason, retry=True, halts=True)
    _record(writer, conn, enter, view, outcome)
    if raise_errors and outcome.event_id is None:
        if outcome.reason == REASON_TEXT:
            raise InvalidEventError("a START text restores nothing; the way back is a form (verification 'otp' or none)")
        raise InvalidEventError(f"the post is stored and no event was written: {outcome.reason}")
    return outcome


class _AlreadyProjected(Exception):
    pass


class _FinalReading(Exception):
    """The pure phase of the reader (the same bytes and facts, no database, no store, no key) produced no event: the one final
    reason, because it repeats on the same bytes by construction. The cause is the reader's own error."""


EDGE_TIMESTAMP_WINDOW_S = 300


def _resolve_site_key(writer, conn, enter, backend, view: PostView, *, field_map: Any, raise_errors: bool) -> "PostView | Outcome":
    """The intake's site-key lookup failed when the post arrived, so the post waits. Repeat the lookup now. The age of the signed
    timestamp is read from the signed time and the post's stored arrival, never from a clock at projection time. The answer is
    stored beside the post as facts; a post that belongs to another organisation than the one it was stored under is stored again
    in its owner's organisation and projected there (an event cites a post of its own organisation). A lookup that is still
    failing raises: the post is not refused or counted, and it is projected again on the next run."""
    from .tenancy.site_keys import resolve_site_key, resolve_site_key_times

    env = edge_envelope.unpack(view.body)
    site_key = next((v for n, v in env.headers if n.lower() == "x-consentvault-site-key"), None)
    owner = resolve_site_key(conn, site_key) if site_key else None
    state = owner.state if owner else "unknown"
    times = resolve_site_key_times(conn, site_key) if owner is not None and view.arrived_epoch is not None else None
    if times is not None:   # the key is judged by the state it was in when the post arrived, not the state it is in now
        arrived = datetime.fromtimestamp(view.arrived_epoch, tz=timezone.utc)
        revoked_at, retired_at = times
        state = "revoked" if revoked_at is not None and revoked_at <= arrived else \
            "source_retired" if retired_at is not None and retired_at <= arrived else "active"
    found: dict[tuple[str, str], Any] = {("vault", "site_key_state"): state, ("vault", "site_key_lookup"): "resolved"}
    signed = view.facts.get(("vault", "edge_signed_timestamp"))
    window = view.facts.get(("vault", "edge_timestamp_window_s"))
    try:
        fresh = abs(float(view.arrived_epoch) - float(signed)) <= float(window if window is not None else EDGE_TIMESTAMP_WINDOW_S)
        found[("vault", "edge_timestamp")] = "fresh" if fresh else "stale"
    except (TypeError, ValueError):  # loud-failure-exempt: stored as the fact edge_timestamp unreadable, the same as the intake stores it
        found[("vault", "edge_timestamp")] = "unreadable"
    if owner is not None:
        # The key was not read when the post arrived (that is why the lookup is repeated). Its state AT ARRIVAL is worked out from the
        # times it was revoked and its source retired, so the history is the same whenever it is rebuilt. Nothing else of the key's
        # live configuration (its source, brands, origins) is taken in: the post arrived without its settings, so it has the final
        # reason settings_missing_at_arrival, whatever the key's state is when the projection runs.
        if state == "active":
            found[("vault", "credential")] = {"state": "verified", "credential_id": str(owner.credential_id),
                                              "scopes": ["capture"], "via": "edge", "key_state_now": owner.state}
    moved_org = owner is not None and str(owner.org_id) != view.org_id
    if not moved_org:
        try:
            writer.append_facts(conn, enter, view.org_id, view.post_id, view.facts.get(("__key__", "data_key")),
                                [Fact(s, n, v) for (s, n), v in found.items()])
        except (ConsentVaultError, psycopg.Error) as exc:
            _log.error("the answer of a repeated site-key lookup could not be stored beside the post", error=type(exc).__name__)
        return replace(view, facts={**view.facts, **found})
    backend_for = _backend_for(backend, view.intake)
    if not hasattr(backend_for, "reroute"):
        return replace(view, facts={**view.facts, **found})
    newview, new_enter = backend_for.reroute(writer, conn, view, owner, found)
    inner = project_view(writer, conn, new_enter, backend, newview, field_map=field_map, raise_errors=raise_errors)
    _record(writer, conn, enter, view, Outcome(view.post_id, reason="stored_again_in_owner_organisation"))
    return Outcome(view.post_id, event_id=inner.event_id, reason=inner.reason or "stored_again_in_owner_organisation",
                   retry=inner.retry, halts=inner.halts)


def _already(conn, enter, view: PostView) -> Outcome:
    """A second event for this post or request was refused by the database: the event this post already has, or the plain reason
    that an earlier post of the same signed request made the event."""
    with _ctx(conn, enter):
        row = conn.execute("SELECT event_id::text AS event_id FROM consentvault.event_source_post WHERE post_id = %s"
                           " AND role = 'trigger'", (uuid.UUID(view.post_id),)).fetchone()
    return Outcome(view.post_id, event_id=row["event_id"]) if row else Outcome(view.post_id, reason="request_seen_before")


def _record(writer, conn, enter, view: PostView, outcome: Outcome) -> Outcome:
    """Leave the plain outcome beside the post as a fact (appended; the post is never touched)."""
    try:
        fact = Fact("vault", "event_derived", outcome.event_id) if outcome.event_id is not None else \
            Fact("vault", "event_not_derived", outcome.reason)
        writer.append_facts(conn, enter, view.org_id, view.post_id, view.facts.get(("__key__", "data_key")),
                            [fact, Fact("vault", "projection_code_version", CODE_VERSION)])
    except Exception as exc:  # loud-failure-exempt: logged by name; the post is not dropped and no other post of the organisation waits on this record
        _log.error("the outcome of a stored post could not be recorded beside it", error=type(exc).__name__)
    return outcome


def _attempt(conn, enter, org_id: str, post_id: str, error_class: str) -> None:
    """Record, beside the post, that the projection ran and met an error: the code version, the class of the error and the time
    (the database's clock). It is a fact about the post and never a reason it produced no event: the post stays unfinished and is
    projected again on the next run."""
    try:
        with _ctx(conn, enter):
            conn.execute("INSERT INTO consentvault.projection_attempt (org_id, post_id, code_version, error_class)"
                         " VALUES (%s, %s, %s, %s)", (uuid.UUID(org_id), uuid.UUID(post_id), CODE_VERSION, error_class))
    except Exception as exc:  # loud-failure-exempt: logged; the post stays unfinished, is reported by name, and the attempt is recorded on the next run
        _log.error("the attempt on a stored post could not be recorded beside it", error=type(exc).__name__)


def project_post(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, backend: Any, view: PostView, *,
                 field_map: Any = None, raise_errors: bool = False, catch_up: Callable | bool = False,
                 intakes: tuple[str, ...] | None = None) -> Outcome:
    """Project one post just stored. When the caller can read its own posts (``catch_up``: True for the single-company vault, or
    the tenant entry that holds a read scope), every earlier post of every intake that has no outcome is brought up to date
    first, in arrival order (a ``Backends`` holds the writer of each intake this process owns), so a crash before this call never
    changes which of two copies of one request counts or the order of a person's history."""
    if catch_up:
        earlier = project_pending(writer, conn, None if catch_up is True else catch_up, backend, through_seq=view.seq - 1,
                                  intakes=intakes, retry_interval_s=LIVE_RETRY_INTERVAL_SECONDS)
        if any(o.halts for o in earlier) and not _is_stop(view):   # an earlier post could not be projected yet: this one waits behind it
            return Outcome(view.post_id, reason=WAITING, retry=True)   # (a stop never waits: its place in the history is its arrival)
    return project_view(writer, conn, enter, backend, view, field_map=field_map, raise_errors=raise_errors)


def read_view(writer: RawPostWriter, conn: psycopg.Connection, org: str, post_id: str, seq: int, intake: str,
              method: str = "POST", path: str = "/v1/events", arrived_epoch: float | None = None) -> PostView:
    data_key = writer.open_key(conn, uuid.UUID(org), post_id)
    return PostView(org, post_id, seq, intake, writer.read_body(conn, uuid.UUID(org), post_id),
                    {**writer.read_facts(conn, uuid.UUID(org), post_id), ("__key__", "data_key"): data_key}, method, path, arrived_epoch)


HALT_CAP_SECONDS = 900
LIVE_RETRY_INTERVAL_SECONDS = 60.0


@_under_projection_login
def project_pending(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, backend: Any, *,
                    through_seq: int | None = None, intakes: tuple[str, ...] | None = None,
                    retry_interval_s: float | None = None) -> list[Outcome]:
    """Run the projection for every stored post that has no outcome yet, in arrival order. Safe to run any number of times. A
    post's own error is that post's outcome and never the queue's. A faulted post halts the posts behind it only until
    ``HALT_CAP_SECONDS`` have passed since its first recorded attempt (not since it arrived): after that the posts behind it go
    ahead, the faulted post is tried again on every run, and no post blocks the others for long. The posts held behind it are
    returned as unfinished, named, never skipped silently. The live path (``retry_interval_s``) does not try a post again
    while its last attempt is younger than the interval: it stays unfinished and halts as before, and the rebuild (no interval)
    tries it every run."""
    with _ctx(conn, enter):
        rows = conn.execute(
            "SELECT p.org_id::text AS org, p.post_id::text AS post_id, p.seq, p.intake, p.method, p.path,"
            " EXTRACT(EPOCH FROM p.received_at)::float8 AS arrived,"
            " (SELECT EXTRACT(EPOCH FROM (clock_timestamp() - min(a.attempted_at)))::float8 FROM consentvault.projection_attempt a"
            "   WHERE a.org_id = p.org_id AND a.post_id = p.post_id) AS attempt_age_s,"
            " EXTRACT(EPOCH FROM (clock_timestamp() - p.received_at))::float8 AS arrival_age_s,"
            " (SELECT EXTRACT(EPOCH FROM (clock_timestamp() - max(a.attempted_at)))::float8 FROM consentvault.projection_attempt a"
            "   WHERE a.org_id = p.org_id AND a.post_id = p.post_id) AS last_attempt_age_s FROM consentvault.raw_post p"
            " WHERE p.org_id = (SELECT consentvault.current_org()) AND p.kind = 'post'"
            "   AND (%s::bigint IS NULL OR p.seq <= %s) AND (%s::text[] IS NULL OR p.intake = ANY(%s))"
            "   AND NOT EXISTS (SELECT 1 FROM consentvault.event_source_post s WHERE s.org_id = p.org_id"
            "                   AND s.post_id = p.post_id AND s.role = 'trigger')"
            "   AND NOT EXISTS (SELECT 1 FROM consentvault.raw_post_fact f WHERE f.org_id = p.org_id"
            "                   AND f.post_id = p.post_id AND f.name = 'event_not_derived')"
            " ORDER BY p.seq", (through_seq, through_seq, intakes and list(intakes), intakes and list(intakes))).fetchall()
    rows = [r for r in rows if _backend_for(backend, r["intake"]) is not None]
    out: list[Outcome] = []
    for n, r in enumerate(rows):
        if retry_interval_s is not None and r["last_attempt_age_s"] is not None and r["last_attempt_age_s"] < retry_interval_s:
            outcome = Outcome(r["post_id"], reason=WAITING_TO_RETRY, retry=True, halts=True)   # tried a moment ago: the rebuild retries it
        else:
            try:
                with _ctx(conn, enter):
                    view = read_view(writer, conn, r["org"], r["post_id"], r["seq"], r["intake"], r["method"], r["path"], r["arrived"])
            except Exception as exc:  # loud-failure-exempt: logged and handed on as the post's outcome; no error is final
                outcome = _unreadable_post(conn, enter, r, exc)
            else:
                outcome = project_view(writer, conn, enter, backend, view)
        elapsed = r["attempt_age_s"]
        if elapsed is None:   # this run's attempt is the first one recorded; when none could be recorded, count from the post's arrival
            first = _first_attempt_age(conn, enter, r) if outcome.halts else 0.0
            elapsed = first if first is not None else r["arrival_age_s"]
        if outcome.halts and elapsed >= HALT_CAP_SECONDS:
            _log.error("a stored post has not been projectable for a long time; the posts behind it go ahead", elapsed_s=int(elapsed))
            outcome = replace(outcome, halts=False)
        out.append(outcome)
        if outcome.halts:   # a faulted post: nothing later but a stop is projected ahead of this post, the next run repeats it first
            for w in rows[n + 1:]:
                out.append(_project_if_stop(writer, conn, enter, backend, w))
            break
    return out


def _is_stop(view: PostView) -> bool:
    """True when the stored bytes read as a stop. A stop is never held behind another post: its place in a person's history is the
    arrival of its post, so projecting it first changes nothing but how soon it counts."""
    reading = read_post(view.body, None, CODE_VERSION, intake=view.intake, context=_view_context(view))
    return reading.kind == "event" and reading.payload.get("event_type") in ("revoke", "suppress")


def _project_if_stop(writer, conn, enter, backend, w) -> Outcome:
    """A post behind a faulted one: projected now when it is a stop, else named as waiting."""
    try:
        with _ctx(conn, enter):
            view = read_view(writer, conn, w["org"], w["post_id"], w["seq"], w["intake"], w["method"], w["path"], w["arrived"])
        stop = _is_stop(view)
    except Exception as exc:  # loud-failure-exempt: logged by name; the post waits as unfinished and is read again on the next run
        _log.error("a post behind a faulted one could not be read to see whether it is a stop", error=reason_of(exc))
        return Outcome(w["post_id"], reason=WAITING, retry=True)
    if not stop:
        return Outcome(w["post_id"], reason=WAITING, retry=True)
    return project_view(writer, conn, enter, backend, view)


def _first_attempt_age(conn, enter, row) -> float | None:
    """Seconds since the post's first recorded attempt by the database's clock, or None when no attempt row exists."""
    with _ctx(conn, enter):
        found = conn.execute("SELECT EXTRACT(EPOCH FROM (clock_timestamp() - min(attempted_at)))::float8 AS age"
                             " FROM consentvault.projection_attempt WHERE org_id = %s AND post_id = %s",
                             (uuid.UUID(row["org"]), uuid.UUID(row["post_id"]))).fetchone()
    return found["age"]


def _unreadable_post(conn, enter, row, exc: BaseException) -> Outcome:
    """A stored post whose bytes or facts could not be read: no error is final, so it is projected again on the next run."""
    reason = reason_of(exc)
    _log.error("a stored post could not be read; the projection will run again for it", error=reason)
    _attempt(conn, enter, row["org"], row["post_id"], reason)
    return Outcome(row["post_id"], reason=reason, retry=True, halts=True)


def backfill_request_keys(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None) -> int:
    """Record the request key of every stored post that carries one and has none recorded as a column yet: a post stored before the
    column existed, or one whose key was learned in a way that bypassed the writer. The key is read from the post's own stored
    facts (the database alone cannot open them), never recomputed. A post whose facts cannot be opened is logged by name and left
    for the next run; it never stops the others. Returns how many were recorded."""
    with _ctx(conn, enter):
        todo = conn.execute(
            "SELECT DISTINCT f.org_id::text AS org, f.post_id::text AS post_id FROM consentvault.raw_post_fact f"
            " WHERE f.org_id = (SELECT consentvault.current_org()) AND f.source = 'vault' AND f.name = 'request_key'"
            "   AND NOT EXISTS (SELECT 1 FROM consentvault.raw_post_request q WHERE q.org_id = f.org_id AND q.post_id = f.post_id)"
            ).fetchall()
    done = 0
    for r in todo:
        try:
            with _ctx(conn, enter):
                key = writer.read_facts(conn, uuid.UUID(r["org"]), r["post_id"]).get(("vault", "request_key"))
                if isinstance(key, str) and key:
                    RawPostWriter.record_request_key(conn, uuid.UUID(r["org"]), uuid.UUID(r["post_id"]), key)
                    done += 1
        except Exception as exc:  # loud-failure-exempt: logged by post; the next run tries again and no other post waits on it
            _log.error("the request key of a stored post could not be recorded as a column; the next run tries again",
                       post_id=r["post_id"], error=type(exc).__name__)
    return done


def rebuild(conn: psycopg.Connection, *, backend: Any = None, writer: RawPostWriter | None = None,
            enter: Callable | None = None) -> list[Outcome]:
    """Run the projection again over everything stored. A crash between a post's answer and its event is repaired by this and
    nothing else; running it twice changes nothing. Every post's request key is a column first, so an event is placed by the
    earliest post carrying its key."""
    writer = writer or RawPostWriter()
    backfill_request_keys(writer, conn, enter)
    return project_pending(writer, conn, enter, backend or SingleBackend())


class TenantLedgerBackend:
    """Writes the event of one post into the entered organisation's chain with the ledger's tenant append (no capture pipeline:
    the stops and the system events whose evidence is the post itself). ``defaults`` fill fields the post does not carry."""

    takes_arrival = True

    def __init__(self, crypto: Any, *, defaults: Mapping[str, Any] | None = None, region: str | None = None,
                 allowed_purposes=None, enter_for_org: Callable[[str], Callable] | None = None,
                 restricted_login: bool = False) -> None:
        self.crypto, self.defaults, self.region, self.allowed_purposes = crypto, dict(defaults or {}), region, allowed_purposes
        self.enter_for_org = enter_for_org
        self.restricted_login = restricted_login   # True only for the cloud's projection, which runs on the projection login

    def for_post(self, facts: Mapping[tuple[str, str], Any]) -> "TenantLedgerBackend":
        stored = _stored_settings(facts)
        if stored is None:
            return self
        return TenantLedgerBackend(self.crypto, defaults=stored.get("defaults") or {}, region=stored.get("region"),
                                   allowed_purposes=stored.get("allowed_purposes"), enter_for_org=self.enter_for_org,
                                   restricted_login=self.restricted_login)

    def prepare(self, conn, payload: Mapping[str, Any], body: bytes, auth: Auth) -> dict | str:
        fields = {**self.defaults, **{k: v for k, v in payload.items() if v is not None}}
        for required in ("contact", "event_type", "channels", "purposes"):
            if required not in fields:
                return f"missing_field:{required}"
        for name in ("captured_at", "edge_received_at"):
            if isinstance(fields.get(name), str):
                try:
                    fields[name] = datetime.fromisoformat(fields[name].replace("Z", "+00:00"))
                except ValueError:  # loud-failure-exempt: returned as the stored reason bad_<field>
                    return f"bad_{name}"
        normalize_contact(fields["contact"], fields.get("contact_kind"), self.region)   # raises NormalizationError: the contact reads the same every time
        fields.setdefault("method", "checkbox")
        fields.setdefault("origin", "consumer")
        if "payload_b64" in fields:   # the original bytes a restore re-ingests, carried whole inside the post
            text = str(fields.pop("payload_b64"))
            fields["payload"] = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        fields["region"], fields["allowed_purposes"] = self.region, self.allowed_purposes
        check_event_shape(fields)   # the same shape checks the append makes, decided here so they are final
        if self.enter_for_org is not None:
            fields["_org"] = auth.org_id
        return fields

    def apply(self, conn, enter, fields: dict, link: Callable) -> str:
        org = fields.pop("_org", None)
        with (self.enter_for_org(org)(conn) if org and self.enter_for_org is not None else contextlib.nullcontext()):
            with conn.transaction():
                event = record_tenant_event(conn, self.crypto, **fields)
                link(conn, event.event_id)
        return event.event_id


def check_event_shape(f: Mapping[str, Any]) -> None:
    """The write step's checks that depend on the bytes alone, run in the pure phase so they are final (they repeat on the same
    post): a grant needs the consent box checked, a channel, a purpose and wording; a stop carries no box; a text restores nothing."""
    if f.get("event_type") == "grant":
        if f.get("checked") is not True:
            raise UncheckedConsentError("the consent box was not checked; no grant recorded")
        if not _list(f.get("channels")) or not _list(f.get("purposes")):
            raise EmptyConsentError("a grant must name at least one channel and one purpose")
        if not f.get("disclosure_sha256"):
            raise EmptyConsentError("a grant must carry the hash of the disclosure the person saw")
        if f.get("contact_verification") == "inbound_keyword" or f.get("inbound_message") is not None:
            raise InvalidEventError("a START text restores nothing; the way back is a form")
    elif f.get("checked") is not None:
        raise InvalidEventError("'checked' belongs only to a grant")


def write_tenant_event(conn: psycopg.Connection, crypto, *, contact: str, event_type: str, channels, purposes,
                       method: str = "checkbox", origin: str = "consumer", checked: bool | None = None,
                       contact_verification: str = "none", inbound_message: str | None = None,
                       disclosure_sha256: str | None = None, payload: bytes | None = None, **fields) -> Event:
    """The capture pipeline's append: one event in the entered organisation's chain (hash version 2), with the capture rules. A
    grant needs the consent box checked, a channel, a purpose and wording; a verified grant needs the integrator's one-time code
    (``otp``); a text is refused as consent; a stop carries no wording and always records. Called by the pipeline and the restore
    job, the only code that reaches the ledger from here."""
    if event_type == "grant":
        if checked is not True:
            raise UncheckedConsentError("the consent box was not checked; no grant recorded")
        chans, purps = _list(channels), _list(purposes)
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


def write_system_event(conn: psycopg.Connection, crypto: Any, **fields) -> Event:
    """An event the vault writes with no post of its own because the post would hold the very data it is erasing (an erasure's
    stop). The one use; every other event cites its post."""
    return record_tenant_event(conn, crypto, **fields)


def authenticate_text(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, stored: StoredPost,
                      request_key: str, *, defaults: Mapping[str, Any] | None = None, region: str | None = None) -> None:
    """Record, beside a stored reply, that the provider's signature checked out. Written on its own connection and committed
    before anything is projected, so the rebuild can project the reply after a crash."""
    facts = (Fact("vault", "request_signature", "valid"), Fact("vault", "replay", "fresh"),
             Fact("vault", "authenticated_by", "provider"), Fact("vault", "request_key", request_key),
             settings_fact(region=region, defaults=defaults))
    writer.append_facts(conn, enter, stored.org_id, stored.post_id, stored.data_key, facts)


def project_text_reply(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, crypto: Any, stored: StoredPost,
                       body: bytes, *, request_key: str, defaults: Mapping[str, Any], region: str | None = None) -> Outcome:
    """A reply the text provider posted, already stored whole and already authenticated (``authenticate_text``): project it. A
    stop word makes the stop; anything else makes nothing. A failure to write raises, so the caller's transaction (the reply row,
    our answer) stands or falls with the stop. A stop the rebuild already projected is returned as the event it made."""
    with _ctx(conn, enter):
        row = conn.execute("SELECT event_id::text AS event_id FROM consentvault.event_source_post"
                           " WHERE request_key = %s AND role = 'trigger'", (request_key_digest(request_key),)).fetchone()
    if row is not None:
        return Outcome(stored.post_id, event_id=row["event_id"])
    facts = {("vault", "request_signature"): "valid", ("vault", "replay"): "fresh", ("vault", "authenticated_by"): "provider",
             ("vault", "request_key"): request_key, ("__key__", "data_key"): stored.data_key}
    view = PostView(stored.org_id, stored.post_id, stored.seq, "sms_reply", body, facts, arrived_epoch=stored.received_at.timestamp())
    return project_post(writer, conn, enter, TenantLedgerBackend(crypto, defaults=defaults, region=region), view,
                        raise_errors=True)


def record_observed(conn: psycopg.Connection, crypto: Any, *, intake: str, fields: Mapping[str, Any], enter: Callable | None = None,
                    region: str | None = None, allowed_purposes=None, request_key: str | None = None) -> Outcome:
    """An event the vault itself observed (a stop page click, a carrier's refusal, an erasure's stop, a connected system's signal,
    a person marking a reply): the observation is stored whole as a post of its own, then projected, so every event cites a post.
    Raises when the event cannot be written, exactly as the ledger append does."""
    writer = RawPostWriter(crypto=crypto)
    enter = enter or (lambda c: c.transaction())
    body = json.dumps(dict(fields), sort_keys=True, default=_json_default).encode("utf-8")
    facts = [Fact("vault", "request_signature", "valid"), Fact("vault", "replay", "fresh"),
             Fact("vault", "authenticated_by", "system")]
    if request_key:
        facts.append(Fact("vault", "request_key", request_key))
    facts.append(settings_fact(region=region, allowed_purposes=allowed_purposes))
    req = RawRequest(intake=intake, method="POST", path="/v1/events", query="", headers=(("content-type", "application/json"),),
                     body=body, headers_presented_by="local-process", facts=tuple(facts))
    stored = store_raw(writer, conn, enter, req)
    view = PostView(stored.org_id, stored.post_id, stored.seq, intake, body,
                    {**{("vault", f.name): f.value for f in facts}, ("__key__", "data_key"): stored.data_key},
                    arrived_epoch=stored.received_at.timestamp())
    backend = TenantLedgerBackend(crypto, region=region, allowed_purposes=allowed_purposes)
    outcome = project_post(writer, conn, enter, backend, view, raise_errors=True)
    return outcome


def _json_default(v: Any) -> Any:
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, uuid.UUID):
        return str(v)
    raise TypeError(f"{type(v).__name__} is not JSON")


# ---- the library and command line adapters' way in -----------------------------------------------------------------------

def submit(conn: psycopg.Connection, *, intake: str, payload: Mapping[str, Any], region: str | None = None,
           allowed_purposes=None, verified: bool = True, writer: RawPostWriter | None = None) -> Event | StoredWaiting:
    """A caller in this process (the library, the command line) hands its request to the door. The request is stored whole as
    JSON, then projected; the event is returned, or the error that names why none was written is raised, after the post is
    stored either way. When an earlier stored post is unfinished the answer is ``StoredWaiting``: stored, not yet projected,
    projected after the earlier post in arrival order. It is never an invalid-request error."""
    writer = writer or RawPostWriter()
    body = json.dumps(dict(payload), default=_json_default, sort_keys=True).encode("utf-8")
    facts = (Fact("vault", "request_signature", "valid"), Fact("vault", "replay", "fresh"),
             Fact("vault", "authenticated_by", "local" if verified else "shared_secret"),
             settings_fact(region=region, allowed_purposes=allowed_purposes))
    req = RawRequest(intake=intake, method="POST", path="/v1/events", query="", headers=(("content-type", "application/json"),),
                     body=body, headers_presented_by="local-process", facts=facts)
    stored = store_raw(writer, conn, None, req)
    all_facts = {("vault", f.name): f.value for f in facts}
    all_facts[("__key__", "data_key")] = stored.data_key
    view = PostView(stored.org_id, stored.post_id, stored.seq, intake, body, all_facts, arrived_epoch=stored.received_at.timestamp())
    outcome = project_post(writer, conn, None, SingleBackend(region, allowed_purposes), view, raise_errors=True, catch_up=True)
    if outcome.event_id is None and outcome.reason == WAITING:
        return StoredWaiting(stored.post_id, stored.seq)
    return event_by_id(conn, outcome.event_id)


def event_by_id(conn: psycopg.Connection, event_id: str) -> Event:
    row = conn.execute("SELECT seq, event_id::text AS event_id, row_hash, prev_hash FROM consentvault.event WHERE event_id = %s",
                       (uuid.UUID(event_id),)).fetchone()
    return Event(seq=row["seq"], event_id=row["event_id"], row_hash=row["row_hash"], prev_hash=row["prev_hash"])
