"""The Twenty CRM REST API, as the connector uses it (contracts: twenty.md sections 1.3 to 1.7, 2.3, 3.2, 3.3, 7).

Every call goes through a ``CallTransport``: in production the egress door's ``POST /call`` (``webhook.EgressTransport.call``),
which refuses private addresses and allows 10 seconds; in the contract suite a local stand-in that skips only the address
check. Nothing here opens a socket itself.

Facts read from a running Twenty v2.46.0 (2026-10-31, the server's own code and its answers; the contract suite re-proves each
on every tested version):
- People live at ``/rest/people``; a list answers ``{"data": {"people": [...]}, "totalCount", "pageInfo": {"endCursor",
  "hasNextPage"}}``; one Person ``{"data": {"person": {...}}}``; a PATCH ``{"data": {"updatePerson": {...}}}``.
- Filters read ``field[op]:"value"``, combined with ``and(...)``; ``updatedAt[gt]``, ``emails.primaryEmail[ilike]`` and
  ``deletedAt[is]:NOT_NULL`` (a soft-deleted Person is listed only through that filter, and answers 404 by id).
- ``DELETE /rest/people/{id}`` with no parameter is a HARD delete; ``?soft_delete=true`` is the soft one; a restore is
  ``PATCH /rest/people/{id}/restore``.
- A phone is ``{primaryPhoneNumber, primaryPhoneCallingCode ("+1"), primaryPhoneCountryCode ("US"), additionalPhones:
  [{number, callingCode, countryCode}]}``; an email ``{primaryEmail, additionalEmails: [str]}``.
- Fields are created with ``POST /rest/metadata/fields`` ``{objectMetadataId, name, label, type}`` (answers the field, 201);
  ``GET /rest/metadata/objects`` lists objects with their fields.
- A webhook carries ``X-Twenty-Webhook-Timestamp`` (milliseconds since the epoch, as text) and ``X-Twenty-Webhook-Signature``,
  the hex HMAC-SHA256 of ``"{timestamp}:{body}"`` where the body is the exact JSON sent; Twenty waits 5 seconds and does not
  retry a failed delivery. The body is ``{targetUrl, eventName, objectMetadata: {id, nameSingular}, workspaceId, webhookId,
  eventDate, userId, workspaceMemberId, record, updatedFields?}``.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Protocol

from ...errors import NormalizationError
from ...normalize import normalize_email, normalize_phone
from ..errors import SyncError, TransportError

PEOPLE = "/rest/people"
MAX_POINTS = 20
PAGE = 60

STATUS_FIELDS = {"sms": "cvStatusSms", "voice": "cvStatusVoice", "artificial_voice": "cvStatusAiVoice", "email": "cvStatusEmail"}
F_FLAG, F_CHECK, F_CHECK_AT, F_SEQ, F_LINK = "cvStopFlag", "cvLastCheck", "cvLastCheckAt", "cvStateSeq", "cvEvidenceLink"
FIELDS = {**{f: "TEXT" for f in STATUS_FIELDS.values()}, F_FLAG: "BOOLEAN", F_CHECK: "TEXT", F_CHECK_AT: "DATE_TIME",
          F_SEQ: "TEXT", F_LINK: "TEXT"}
OWNED = (*STATUS_FIELDS.values(), F_CHECK, F_CHECK_AT, F_SEQ, F_LINK)   # the vault is the only writer of these eight
FIELD_LABELS = {"cvStatusSms": "ConsentVault SMS", "cvStatusVoice": "ConsentVault voice",
                "cvStatusAiVoice": "ConsentVault AI voice", "cvStatusEmail": "ConsentVault email",
                "cvStopFlag": "Do not contact", "cvLastCheck": "ConsentVault last check",
                "cvLastCheckAt": "ConsentVault last check at", "cvStateSeq": "ConsentVault sequence",
                "cvEvidenceLink": "ConsentVault evidence"}
RECORD_URL = "{base_url}/object/person/{record_id}"
EVIDENCE_URL = "https://app.consentvault.ai/evidence?record={record_id}"


class TwentyError(SyncError):
    """A Twenty answer the connector cannot use. ``error_class`` is one of the outbox's classes; ``outcome`` retry or dead."""

    def __init__(self, message: str, *, error_class: str, outcome: str, http_status: int | None = None) -> None:
        super().__init__(message)
        self.error_class, self.outcome, self.http_status = error_class, outcome, http_status


class PersonGone(SyncError):
    """A Person id answered 404: soft-deleted (restorable) or destroyed. Never an error class; the caller decides."""


@dataclass(frozen=True)
class CallResult:
    """What came back through the door. kind: response (status set), timeout, unreachable, refused (the door will never send).
    ``body`` is parsed JSON (or None); it is never logged."""
    kind: str
    status: int | None = None
    headers: dict = field(default_factory=dict)
    body: Any = None
    detail: str = ""

    def __repr__(self) -> str:
        return f"CallResult(kind={self.kind!r}, status={self.status!r})"


class CallTransport(Protocol):
    def call(self, method: str, url: str, headers: dict[str, str], payload: Any | None) -> CallResult: ...


def classify(res: CallResult, *, stored_id: bool = False) -> None:
    """Raise the named error for any answer that is not 2xx (twenty.md 2.3, one class per status). A 404 on a stored Person id
    raises ``PersonGone`` (not an error); on a collection path it is ``schema_changed``."""
    if res.kind == "timeout":
        raise TwentyError("Twenty did not answer within the call deadline", error_class="timeout", outcome="retry")
    if res.kind == "unreachable":
        raise TwentyError(f"Twenty could not be reached: {res.detail}", error_class="unreachable", outcome="retry")
    if res.kind == "refused":
        raise TwentyError(f"the egress door refuses this address: {res.detail}", error_class="target_private", outcome="dead")
    if res.kind != "response" or res.status is None:
        raise TransportError(f"unknown call result {res!r}")
    s = res.status
    if 200 <= s < 300:
        return
    if s in (401, 403):
        raise TwentyError(f"Twenty refused the API key ({s})", error_class="key_rejected", outcome="dead", http_status=s)
    if s == 404 and stored_id:
        raise PersonGone("the Person answered 404")
    if s == 404:
        raise TwentyError("Twenty answered 404 on a collection path: the API moved", error_class="schema_changed",
                          outcome="retry", http_status=s)
    if s in (408, 429):
        raise TwentyError(f"Twenty answered {s}", error_class="http_4xx", outcome="retry", http_status=s)
    if 500 <= s < 600:
        raise TwentyError(f"Twenty answered {s}", error_class="http_5xx", outcome="retry", http_status=s)
    raise TwentyError(f"Twenty answered {s}", error_class="http_4xx", outcome="dead", http_status=s)


def _quote(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _norm_point(kind: str, raw, calling: str | None, region: str | None) -> str | None:
    """The normalised contact point, or None when the Twenty value is not one (twenty.md 1.7: only what normalises is a
    contact point; ``unmatchable_points`` counts the rest so they are never invisible)."""
    if not raw or not isinstance(raw, str):
        return None
    try:
        if kind == "email":
            return normalize_email(raw)
        digits = re.sub(r"[^0-9+]", "", raw)
        code = re.sub(r"[^0-9]", "", calling or "")
        return normalize_phone(("+" + code + digits.lstrip("+")) if code and not digits.startswith("+") else raw, region)
    except NormalizationError:
        return None  # loud-failure-exempt: a value that does not normalise is not a contact point; unmatchable_points counts it


def _raw_points(person: dict) -> list[tuple[str, Any, str | None]]:
    out: list[tuple[str, Any, str | None]] = []
    emails = person.get("emails") or {}
    out.append(("email", emails.get("primaryEmail"), None))
    for e in emails.get("additionalEmails") or []:
        out.append(("email", e.get("email") if isinstance(e, dict) else e, None))
    phones = person.get("phones") or {}
    out.append(("phone", phones.get("primaryPhoneNumber"), phones.get("primaryPhoneCallingCode")))
    for p in phones.get("additionalPhones") or []:
        if isinstance(p, dict):
            out.append(("phone", p.get("number"), p.get("callingCode")))
    return [r for r in out if r[1]]


def contact_points(person: dict, region: str | None = None) -> list[tuple[str, str]]:
    """Every contact point on a Person, normalised as the vault normalises (twenty.md 1.7): primary and additional emails and
    phones, deduplicated, at most ``MAX_POINTS``."""
    out: list[tuple[str, str]] = []
    for kind, raw, calling in _raw_points(person):
        norm = _norm_point(kind, raw, calling, region)
        if norm is not None and (kind, norm) not in out:
            out.append((kind, norm))
    return out[:MAX_POINTS]


def unmatchable_points(person: dict, region: str | None = None) -> int:
    """Contact values on the Person that do not normalise (counted on the activity list, never silently dropped)."""
    return sum(1 for kind, raw, calling in _raw_points(person) if _norm_point(kind, raw, calling, region) is None)


def over_cap(person: dict, region: str | None = None) -> bool:
    seen = {(k, _norm_point(k, r, c, region)) for k, r, c in _raw_points(person)}
    return len({s for s in seen if s[1] is not None}) > MAX_POINTS


def parse_seq(value) -> int | None:
    """``cvStateSeq`` compared as an integer, never as a string ("9" is not above "10"). None when it is not one."""
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,18}", value):
        return int(value)
    return None


def record_link(base_url: str, record_id: str) -> str:
    """The customer's own record page for a Person (confirmed on Twenty v2.46.0: route /object/:objectNameSingular/:id)."""
    return RECORD_URL.format(base_url=base_url.rstrip("/"), record_id=record_id)


class TwentyClient:
    """One Twenty instance, through the door. ``before_call`` runs before every call (the pacing bucket and the lease
    heartbeat in the worker); it raises to stop the call."""

    def __init__(self, base_url: str, api_key: str, transport: CallTransport, *, before_call=None) -> None:
        if not base_url.startswith(("https://", "http://")):
            raise TwentyError("the Twenty address must be an https origin", error_class="http_4xx", outcome="dead")
        self.base_url = base_url.rstrip("/")
        self._key = api_key
        self.transport = transport
        self.before_call = before_call
        self.calls = 0

    def __repr__(self) -> str:   # the key never reaches a log line
        return f"TwentyClient(base_url={self.base_url!r})"

    def _call(self, method: str, path: str, payload: Any | None = None, query: dict | None = None) -> CallResult:
        if self.before_call is not None:
            self.before_call()
        url = self.base_url + path + (("?" + urllib.parse.urlencode(query, safe=":[]()\",*")) if query else "")
        self.calls += 1
        return self.transport.call(method, url, {"Authorization": f"Bearer {self._key}", "Accept": "application/json",
                                                 "Content-Type": "application/json"}, payload)

    # People -----------------------------------------------------------------------------------------------------------
    def people(self, *, filter: str | None = None, limit: int = PAGE, starting_after: str | None = None,
               order_by: str | None = None) -> tuple[list[dict], dict]:
        q: dict = {"limit": str(min(max(limit, 1), PAGE))}
        if filter:
            q["filter"] = filter
        if starting_after:
            q["starting_after"] = starting_after
        if order_by:
            q["order_by"] = order_by
        res = self._call("GET", PEOPLE, query=q)
        classify(res)
        try:
            people = res.body["data"]["people"]
            info = res.body.get("pageInfo") or {}
        except (TypeError, KeyError, AttributeError) as exc:
            raise TwentyError("the People list has a shape the connector does not know", error_class="schema_changed",
                              outcome="retry", http_status=res.status) from exc
        if not isinstance(people, list):
            raise TwentyError("the People list is not a list", error_class="schema_changed", outcome="retry")
        return people, info

    def person(self, person_id: str) -> dict:
        res = self._call("GET", f"{PEOPLE}/{urllib.parse.quote(person_id, safe='')}")
        classify(res, stored_id=True)
        try:
            return res.body["data"]["person"]
        except (TypeError, KeyError) as exc:
            raise TwentyError("a Person has a shape the connector does not know", error_class="schema_changed",
                              outcome="retry") from exc

    def patch(self, person_id: str, fields: dict) -> dict:
        res = self._call("PATCH", f"{PEOPLE}/{urllib.parse.quote(person_id, safe='')}", fields)
        classify(res, stored_id=True)
        try:
            return res.body["data"]["updatePerson"]
        except (TypeError, KeyError) as exc:
            raise TwentyError("an update answer has a shape the connector does not know", error_class="schema_changed",
                              outcome="retry") from exc

    def create_person(self, body: dict) -> dict:
        res = self._call("POST", PEOPLE, body)
        classify(res)
        try:
            return res.body["data"]["createPerson"]
        except (TypeError, KeyError) as exc:
            raise TwentyError("a create answer has a shape the connector does not know", error_class="schema_changed",
                              outcome="retry") from exc

    def delete_person(self, person_id: str, *, soft: bool) -> None:
        q = "?soft_delete=true" if soft else ""
        res = self._call("DELETE", f"{PEOPLE}/{urllib.parse.quote(person_id, safe='')}{q}")
        classify(res, stored_id=True)

    def restore_person(self, person_id: str) -> None:
        res = self._call("PATCH", f"{PEOPLE}/{urllib.parse.quote(person_id, safe='')}/restore")
        classify(res, stored_id=True)

    def is_soft_deleted(self, person_id: str) -> bool:
        """Is this id among Twenty's soft-deleted records (the nightly scan tells a deleted record from a destroyed one)?"""
        people, _ = self.people(filter=f"and(id[eq]:{_quote(person_id)},deletedAt[is]:NOT_NULL)", limit=1)
        return bool(people)

    def find(self, kind: str, norm: str, *, region: str | None = None, cap: int = 11) -> list[dict]:
        """People whose contact points include ``(kind, norm)``, confirmed by normalising each candidate. Email: primary by a
        case-insensitive filter. Phone: primary by the last seven digits, then exact. Additional points are matched only by
        the reconcile scan (twenty.md 1.7)."""
        if kind == "email":
            flt = f"emails.primaryEmail[ilike]:{_quote(norm)}"
        else:
            flt = f"phones.primaryPhoneNumber[like]:{_quote('%' + norm[-7:])}"
        found, after = [], None
        while len(found) < cap:
            people, info = self.people(filter=flt, limit=PAGE, starting_after=after)
            found += [p for p in people if (kind, norm) in contact_points(p, region)]
            if not info.get("hasNextPage") or not info.get("endCursor"):
                break
            after = info["endCursor"]
        return found[:cap]

    # The data model ---------------------------------------------------------------------------------------------------
    def person_object(self) -> dict:
        res = self._call("GET", "/rest/metadata/objects", query={"limit": "200"})
        classify(res)
        try:
            objs = res.body["data"]
            if isinstance(objs, dict):
                objs = objs.get("objects") or []
            return next(o for o in objs if o.get("nameSingular") == "person")
        except (TypeError, KeyError, StopIteration, AttributeError) as exc:
            raise TwentyError("the data model has no Person object the connector knows", error_class="schema_changed",
                              outcome="retry") from exc

    def create_field(self, object_id: str, name: str, ftype: str) -> dict:
        res = self._call("POST", "/rest/metadata/fields", {"objectMetadataId": object_id, "name": name,
                                                          "label": FIELD_LABELS.get(name, name), "type": ftype})
        classify(res)
        return res.body if isinstance(res.body, dict) else {}


def schema_fingerprint(person_object: dict) -> str:
    """A hash of the People field names and types the connector depends on (twenty.md 7): the drift detector."""
    fields = sorted((f.get("name"), f.get("type")) for f in person_object.get("fields") or []
                    if f.get("name") in (*FIELDS, "emails", "phones", "updatedAt", "deletedAt", "id"))
    return hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest()


def verify_signature(secret: bytes, timestamp: str, raw_body: bytes, signature: str) -> bool:
    """Twenty's webhook signature: hex HMAC-SHA256 of ``"{timestamp}:{body}"`` over the exact bytes received."""
    import hmac

    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        return False
    want = hmac.new(secret, timestamp.encode("ascii", "replace") + b":" + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, signature)


def sign(secret: bytes, timestamp: str, raw_body: bytes) -> str:
    """What Twenty sends (used by the tests and the self-test's webhook check)."""
    import hmac

    return hmac.new(secret, timestamp.encode("ascii") + b":" + raw_body, hashlib.sha256).hexdigest()
