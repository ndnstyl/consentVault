"""Reading the exact values out of a stored post: the consent box, the decision time and the wording, as sent.

Extraction reads the bytes the raw post store holds with a tokenising reader that reports every occurrence of a path
together with the byte range of its value, so nothing is parsed into a language value and written back out: a JSON
``true`` is copied as ``true``, ``"on"`` as ``"on"`` with its quotes, ``"2026-10-20 09:12"`` exactly as written, escapes and
all. A path that occurs twice gives both occurrences in byte order; a path that does not occur reads "not sent". Nothing
here decides whether a post is stored, linked, shown or exported, and no value is ever filled, defaulted or corrected.

A form's map (``form_field_map``, data-model.md section 3) says where each field lives. A form with no map has its consent
read as ``unmapped`` and an alarm names it; the post stays stored. A reader error is ``body_unreadable`` for each field;
the post stays stored.

No model, no guess: the same bytes and the same map give the same readings on every run.
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable
from urllib.parse import unquote_to_bytes

import psycopg

from .ledger import canonical_dumps

FIELDS = ("consent", "decision_time", "wording", "wording_hash", "contact", "seller", "form_version", "checkbox_default",
          "submit_context", "third_party_cert", "jurisdiction", "channel_scope")
SENT, NOT_SENT, MANY, UNMAPPED, UNREADABLE = "sent", "not_sent", "sent_more_than_once", "unmapped", "body_unreadable"
COL_VALUES = "raw_post_field.values"
EXTRACTOR_VERSION = 1


class Unreadable(Exception):
    """The body cannot be read in the format the map names (never a reason to drop the post)."""


# JSON tokeniser -----------------------------------------------------------------------------------------------------------

_WS = b" \t\r\n"
_STR = re.compile(rb'"(?:[^"\\]|\\.)*"', re.DOTALL)
_LIT = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null")
_SKIP = re.compile(rb'"(?:[^"\\]|\\.)*"|[\[\]{}]', re.DOTALL)
_MAX_DEPTH = 400


def pointer_tokens(pointer: str) -> tuple[str, ...]:
    """A JSON pointer ("/a/b/0", "/" is the empty key, "" the whole document) as its decoded reference tokens."""
    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise Unreadable(f"{pointer!r} is not a JSON pointer")
    return tuple(t.replace("~1", "/").replace("~0", "~") for t in pointer[1:].split("/"))


def json_occurrences(body: bytes, pointers: Iterable[str]) -> dict[str, list[bytes]]:
    """For each pointer, the raw bytes of every value found at it, in byte order (a repeated key gives each one).

    Raises ``Unreadable`` when the body is not JSON. The returned bytes are slices of ``body`` untouched."""
    wanted: dict[tuple[str, ...], str] = {pointer_tokens(p): p for p in pointers}
    prefixes = {t[:i] for t in wanted for i in range(len(t) + 1)}
    found: dict[str, list[bytes]] = {p: [] for p in wanted.values()}
    n = len(body)

    def ws(i: int) -> int:
        while i < n and body[i] in _WS:
            i += 1
        return i

    def skip_container(i: int) -> int:
        depth = 0
        for m in _SKIP.finditer(body, i):
            tok = m.group()
            if tok in (b"{", b"["):
                depth += 1
            elif tok in (b"}", b"]"):
                depth -= 1
                if depth == 0:
                    return m.end()
        raise Unreadable("the body ends inside an object or array")

    def members(i: int, path: tuple[str, ...], depth: int) -> int:
        i = ws(i + 1)
        if body[i:i + 1] == b"}":
            return i + 1
        for _ in range(n + 1):  # every member consumes at least one byte, so the body's length bounds the loop
            m = _STR.match(body, ws(i))
            if m is None:
                raise Unreadable("an object key is not a string")
            try:
                key = json.loads(m.group().decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise Unreadable("an object key cannot be read") from exc
            i = ws(m.end())
            if body[i:i + 1] != b":":
                raise Unreadable("an object key is not followed by a colon")
            i = ws(value(i + 1, path + (key,), depth + 1))
            d = body[i:i + 1]
            if d == b"}":
                return i + 1
            if d != b",":
                raise Unreadable("an object member is not followed by a comma or a closing brace")
            i += 1
        raise Unreadable("an object does not end")

    def elements(i: int, path: tuple[str, ...], depth: int) -> int:
        i = ws(i + 1)
        if body[i:i + 1] == b"]":
            return i + 1
        for idx in range(n + 1):
            i = ws(value(i, path + (str(idx),), depth + 1))
            d = body[i:i + 1]
            if d == b"]":
                return i + 1
            if d != b",":
                raise Unreadable("an array element is not followed by a comma or a closing bracket")
            i += 1
        raise Unreadable("an array does not end")

    def value(i: int, path: tuple[str, ...], depth: int) -> int:
        if depth > _MAX_DEPTH:
            raise Unreadable("the body nests deeper than the reader follows")
        i = ws(i)
        if i >= n:
            raise Unreadable("the body ends where a value was expected")
        start, c = i, body[i:i + 1]
        descend = path in prefixes
        if c == b"{":
            end = members(i, path, depth) if descend else skip_container(i)
        elif c == b"[":
            end = elements(i, path, depth) if descend else skip_container(i)
        elif c == b'"':
            m = _STR.match(body, i)
            if m is None:
                raise Unreadable("a string is not closed")
            end = m.end()
        else:
            m = _LIT.match(body, i)
            if m is None:
                raise Unreadable("a value is not JSON")
            end = m.end()
        if path in wanted:
            found[wanted[path]].append(bytes(body[start:end]))
        return end

    try:
        end = value(3 if body.startswith(b"\xef\xbb\xbf") else 0, (), 0)
        if ws(end) != n:
            raise Unreadable("the body holds more than one JSON value")
    except RecursionError as exc:
        raise Unreadable("the body nests deeper than the reader follows") from exc
    return found


# Form bodies --------------------------------------------------------------------------------------------------------------

def form_occurrences(body: bytes, names: Iterable[str]) -> dict[str, list[bytes]]:
    """Every occurrence of each field name in an ``application/x-www-form-urlencoded`` body, in byte order; the value is the
    encoded text as written (percent escapes and plus signs kept)."""
    found: dict[str, list[bytes]] = {n: [] for n in names}
    if not body:
        return found
    for part in body.split(b"&"):
        if part == b"":
            continue
        raw_name, _, raw_value = part.partition(b"=")
        name = unquote_to_bytes(raw_name.replace(b"+", b" ")).decode("utf-8", "replace")
        if name in found:
            found[name].append(raw_value)
    return found


def multipart_occurrences(body: bytes, content_type: str | None, names: Iterable[str]) -> dict[str, list[bytes]]:
    """Every occurrence of each field name in a ``multipart/form-data`` body: the raw bytes of the part between its blank line
    and its delimiter."""
    found: dict[str, list[bytes]] = {n: [] for n in names}
    m = re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))', content_type or "", re.I)
    if m is None:
        raise Unreadable("a multipart body with no boundary in its content type")
    delim = b"--" + (m.group(1) or m.group(2)).encode("latin-1", "replace")
    if delim not in body:
        raise Unreadable("the multipart boundary does not occur in the body")
    for chunk in body.split(delim)[1:]:
        if chunk.startswith(b"--"):
            break
        head, sep, rest = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        nm = re.search(rb'name="((?:[^"\\]|\\.)*)"', head, re.I)
        if nm is None:
            continue
        name = nm.group(1).decode("utf-8", "replace")
        if name in found:
            found[name].append(rest[:-2] if rest.endswith(b"\r\n") else rest)
    return found


# Field maps ---------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class FieldMap:
    """Where a form puts its fields. ``map_version`` 0 is a map built into the vault (not a stored row)."""
    body_format: str = "json"
    consent_paths: tuple[str, ...] = ()
    consent_ticked_value: str | None = None
    decision_time_path: str | None = None
    wording_path: str | None = None
    wording_hash_path: str | None = None
    seller_paths: tuple[str, ...] = ()
    form_version_path: str | None = None
    checkbox_default_path: str | None = None
    submit_context_path: str | None = None
    third_party_cert_path: str | None = None
    jurisdiction_path: str | None = None
    channel_scope_path: str | None = None
    contact_paths: tuple[tuple[str, str], ...] = ()
    map_version: int = 0
    label: str = "map"
    # whether a missing box is something an operator should hear about. A form's own map says yes; the events API map says no,
    # because a stop carries no box (the reading still records "not sent", and the transitional event records why it was not a grant).
    box_expected: bool = True

    def paths(self, name: str) -> tuple[str, ...]:
        if name == "consent":
            return tuple(self.consent_paths)
        if name == "contact":
            return tuple(p for p, _ in self.contact_paths)
        if name == "seller":
            return tuple(self.seller_paths)
        p = getattr(self, f"{name}_path")
        return (p,) if p else ()


# The widget posts {contact, checked, decided_at, disclosure_text, disclosure_sha256, ...}; the events API takes the event fields.
WIDGET_MAP = FieldMap(body_format="json", consent_paths=("/checked",), decision_time_path="/decided_at",
                      wording_path="/disclosure_text", wording_hash_path="/disclosure_sha256",
                      contact_paths=(("/contact", "detect"),), label="built_in:widget")
EVENTS_API_MAP = FieldMap(body_format="json", consent_paths=("/checked",), decision_time_path="/captured_at",
                          wording_path=None, wording_hash_path="/disclosure_sha256",
                          contact_paths=(("/contact", "detect"),), label="built_in:events_api", box_expected=False)
BUILT_IN_BY_INTAKE = {"edge_site_key": WIDGET_MAP, "edge_single": WIDGET_MAP, "gateway": WIDGET_MAP,
                      "api": EVENTS_API_MAP, "api_single": EVENTS_API_MAP}


def load_field_map(conn: psycopg.Connection, source_id: uuid.UUID | str | None, intake: str) -> FieldMap | None:
    """The map in force for a post: the newest version for its source, else the organisation's default (source-less)
    newest version, else the vault's built-in map for the intake, else None (an unmapped form)."""
    rows = conn.execute(
        "SELECT * FROM consentvault.form_field_map WHERE org_id = (SELECT consentvault.current_org())"
        " AND (source_id IS NOT DISTINCT FROM %s OR source_id IS NULL)"
        " ORDER BY (source_id IS NULL), map_version DESC LIMIT 1",
        (uuid.UUID(str(source_id)) if source_id else None,)).fetchall()
    if rows:
        r = rows[0]
        return FieldMap(
            body_format=r["body_format"], consent_paths=tuple(r["consent_paths"] or ()),
            consent_ticked_value=r["consent_ticked_value"], decision_time_path=r["decision_time_path"],
            wording_path=r["wording_path"], wording_hash_path=r["wording_hash_path"],
            seller_paths=tuple(r["seller_paths"] or ()), form_version_path=r["form_version_path"],
            checkbox_default_path=r["checkbox_default_path"], submit_context_path=r["submit_context_path"],
            third_party_cert_path=r["third_party_cert_path"], jurisdiction_path=r["jurisdiction_path"],
            channel_scope_path=r["channel_scope_path"],
            contact_paths=tuple((c["path"], c.get("kind", "detect")) for c in (r["contact_paths"] or [])),
            map_version=r["map_version"], label=f"row:{r['map_version']}")
    return BUILT_IN_BY_INTAKE.get(intake)


def add_field_map(conn: psycopg.Connection, *, set_by: str, source_id: uuid.UUID | str | None = None, body_format: str = "json",
                  consent_paths: Iterable[str] = (), consent_ticked_value: str | None = None,
                  contact_paths: Iterable[tuple[str, str]] = (), **paths) -> int:
    """Append the next version of a form's field map (never an edit: an old version stays as it was). Runs inside the entered
    organisation on a login that may write maps (the operator console's). Returns the new version number. ``paths`` may name any
    of decision_time_path, wording_path, wording_hash_path, seller_paths, form_version_path, checkbox_default_path,
    submit_context_path, third_party_cert_path, jurisdiction_path, channel_scope_path."""
    allowed = {"decision_time_path", "wording_path", "wording_hash_path", "seller_paths", "form_version_path",
               "checkbox_default_path", "submit_context_path", "third_party_cert_path", "jurisdiction_path", "channel_scope_path"}
    unknown = set(paths) - allowed
    if unknown:
        raise ValueError(f"unknown field map settings: {sorted(unknown)}")
    source = uuid.UUID(str(source_id)) if source_id else None
    row = conn.execute(
        "SELECT coalesce(max(map_version), 0) + 1 AS v FROM consentvault.form_field_map"
        " WHERE org_id = (SELECT consentvault.current_org()) AND source_id IS NOT DISTINCT FROM %s", (source,)).fetchone()
    version = row["v"]
    cols = ["source_id", "map_version", "consent_ticked_value", "body_format", "consent_paths", "contact_paths", "set_by", *paths]
    vals = [source, version, consent_ticked_value, body_format, list(consent_paths),
            json.dumps([{"path": p, "kind": k} for p, k in contact_paths]), set_by, *paths.values()]
    conn.execute(f"INSERT INTO consentvault.form_field_map ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))})", vals)
    return version


def list_field_maps(conn: psycopg.Connection, source_id: uuid.UUID | str | None = None) -> list[dict]:
    """Every stored version of the maps of one source (or the organisation default), oldest first, with who set it and when."""
    source = uuid.UUID(str(source_id)) if source_id else None
    return [dict(r) for r in conn.execute(
        "SELECT * FROM consentvault.form_field_map WHERE org_id = (SELECT consentvault.current_org())"
        " AND source_id IS NOT DISTINCT FROM %s ORDER BY map_version", (source,)).fetchall()]


# Readings -----------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Reading:
    field: str
    state: str
    values: tuple[bytes, ...] = ()
    decision_time_parsed: datetime | None = field(default=None, compare=False)

    @property
    def occurrences(self) -> int:
        return len(self.values)


def _value_text(raw: bytes):
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:  # loud-failure-exempt: bytes that are not text are stored as base64, exactly, never replaced
        return {"b64": base64.b64encode(raw).decode("ascii")}


def values_json(values: Iterable[bytes]) -> bytes:
    """The stored form of a reading's values: a JSON list holding the exact text of each occurrence, in order."""
    return canonical_dumps([_value_text(v) for v in values]).encode("utf-8")


def parse_decision_time(raw: bytes) -> datetime | None:
    """The sent decision time as a timestamp, for sorting only. None when it cannot be read as an ISO date and time with
    a zone; the sent text is never changed and a missing zone is never filled."""
    try:
        text = raw.decode("utf-8")
        if raw[:1] == b'"':
            text = json.loads(text)
        t = datetime.fromisoformat(text.strip().replace("Z", "+00:00").replace(" ", "T", 1))
        if t.tzinfo is None:
            return None
        return t.astimezone(timezone.utc)
    except (UnicodeDecodeError, ValueError, TypeError, OverflowError):  # loud-failure-exempt: the sorting copy is optional; the sent text is stored whole beside it
        return None


def read_fields(body: bytes, content_type: str | None, fmap: FieldMap | None) -> list[Reading]:
    """Every field the map names, read from the exact stored bytes. Pure and deterministic."""
    if fmap is None:
        return [Reading("consent", UNMAPPED)]
    wanted = {name: fmap.paths(name) for name in FIELDS}
    all_paths = [p for ps in wanted.values() for p in ps]
    try:
        if fmap.body_format == "json":
            found = json_occurrences(body, all_paths)
        elif fmap.body_format == "form_urlencoded":
            found = form_occurrences(body, all_paths)
        elif fmap.body_format == "multipart":
            found = multipart_occurrences(body, content_type, all_paths)
        else:
            raise Unreadable("a text body has no named fields")
    except Unreadable:  # loud-failure-exempt: the failure is the stored state body_unreadable on each field, and the caller raises its alarm
        return [Reading(name, UNREADABLE) for name in FIELDS if wanted[name] or name == "consent"]
    out: list[Reading] = []
    for name in FIELDS:
        paths = wanted[name]
        if not paths:
            if name == "consent":
                out.append(Reading("consent", UNMAPPED))
            continue
        values = tuple(v for p in paths for v in found[p])
        state = NOT_SENT if not values else SENT if len(values) == 1 else MANY
        parsed = parse_decision_time(values[0]) if name == "decision_time" and values else None
        out.append(Reading(name, state, values, parsed))
    return out


# Storing readings ---------------------------------------------------------------------------------------------------------

def write_readings(conn: psycopg.Connection, enter: Callable | None, *, org: uuid.UUID | str, post_id: uuid.UUID | str,
                   map_version: int, readings: Iterable[Reading], data_key: bytes | None) -> int:
    """Append one ``raw_post_field`` row per reading, in one transaction. Never touches the post."""
    from .tenancy import crypto as tc

    org, post_id = uuid.UUID(str(org)), uuid.UUID(str(post_id))
    n = 0
    ctx = enter(conn) if enter is not None else conn.transaction()
    with ctx:
        for r in readings:
            raw = values_json(r.values) if r.values else None
            ct = None if raw is None else (raw if data_key is None else
                                           tc.encrypt_field(data_key, org, f"{post_id}:{map_version}:{r.field}", COL_VALUES, raw))
            conn.execute(
                "INSERT INTO consentvault.raw_post_field (org_id, post_id, map_version, field, state, values_ct, occurrences,"
                " decision_time_parsed) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (org, post_id, map_version, r.field, r.state, ct, r.occurrences, r.decision_time_parsed))
            n += 1
    return n


def read_stored_values(conn: psycopg.Connection, org: uuid.UUID | str, post_id: uuid.UUID | str, field: str,
                       *, map_version: int | None = None, data_key: bytes | None = None) -> dict:
    """The stored reading of one field of one post (lowest map version, the one in force at arrival, unless named):
    ``{"state", "map_version", "occurrences", "values": [exact text, ...]}``. Reading needs the evidence read scope;
    ``data_key`` is None for a post stored unencrypted."""
    from .tenancy import crypto as tc

    org, post_id = uuid.UUID(str(org)), uuid.UUID(str(post_id))
    row = conn.execute(
        "SELECT * FROM consentvault.raw_post_field WHERE org_id = %s AND post_id = %s AND field = %s"
        + (" AND map_version = %s" if map_version is not None else "") + " ORDER BY map_version LIMIT 1",
        (org, post_id, field) + ((map_version,) if map_version is not None else ())).fetchone()
    if row is None:
        return {"state": NOT_SENT, "map_version": None, "occurrences": 0, "values": [], "decision_time_parsed": None}
    values: list = []
    if row["values_ct"] is not None:
        blob = bytes(row["values_ct"])
        raw = blob if data_key is None else tc.decrypt_field(
            data_key, org, f"{post_id}:{row['map_version']}:{field}", COL_VALUES, blob)
        values = json.loads(raw)
    return {"state": row["state"], "map_version": row["map_version"], "occurrences": row["occurrences"], "values": values,
            "decision_time_parsed": row["decision_time_parsed"]}
