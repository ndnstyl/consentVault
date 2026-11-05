"""Matching: a person's posts are linked by the contact fingerprint, and a change in consent is shown as history.

The vault records and does not decide. A post's contact value is read from the stored bytes with the form's field map, made
into the contact's fingerprint (``TenantCrypto.contact_fingerprint``, the same one the events and the records list use), and
one ``raw_post_match`` row is appended for each contact point the post carries. The row names the previous post for that
contact point (by the earliest arrival the infrastructure recorded, then the vault's own sequence) and the previous post from
the same capture source, holds the exact consent texts of both posts, and says whether their bytes differ (``changed``), whether
the wording as sent differs (``wording_changed``) and whether the two bodies are byte-identical. A post with no contact point
gets one ``unmatched`` row with a plain reason. Nothing stored is ever updated or deleted: a late arrival that belongs between two
earlier posts appends a new row for the post that follows it, and a reader takes the newest row of the version in force.

No model and no judgment: the same bytes and the same map give the same rows on every run. The consent texts here are copied,
never read for meaning; whether a person consented is the value they sent, shown beside the value they sent before.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterable

import psycopg

from . import extract
from .errors import ConsentVaultError, NormalizationError
from .normalize import detect_kind, normalize_contact
from .rawpost import ENC_NONE

COL_BEFORE = "raw_post_match.consent_before"
COL_AFTER = "raw_post_match.consent_after"
COL_VALUES = extract.COL_VALUES

NO_MAP, NO_CONTACT_PATH, CONTACT_NOT_SENT = "no_map", "no_contact_path", "contact_not_sent"
UNREADABLE_PHONE, UNREADABLE_EMAIL, BODY_UNREADABLE = "contact_unreadable_as_phone", "contact_unreadable_as_email", "body_unreadable"
REASONS = (NO_MAP, NO_CONTACT_PATH, CONTACT_NOT_SENT, UNREADABLE_PHONE, UNREADABLE_EMAIL, BODY_UNREADABLE)
# the plain words an operator reads beside each reason
REASON_TEXT = {
    NO_MAP: "no field map is set for this form, so no contact field is known",
    NO_CONTACT_PATH: "the form's field map names no contact field",
    CONTACT_NOT_SENT: "the post did not carry the contact field the map names",
    UNREADABLE_PHONE: "the contact field was sent but is not readable as a phone number",
    UNREADABLE_EMAIL: "the contact field was sent but is not readable as an email address",
    BODY_UNREADABLE: "the body could not be read in the format the map names",
}
_NO_READING = (extract.UNMAPPED, extract.UNREADABLE)


class LinkError(ConsentVaultError):
    """The link could not be written. The post stays stored and the repair run appends the missing rows."""


@dataclass(frozen=True)
class PostInfo:
    """What linking needs to know about the post being linked (all of it is on the stored row)."""
    post_id: str
    seq: int
    order_at: datetime          # coalesce(edge_received_at, received_at): the earliest arrival the infrastructure recorded
    body_sha256: str


@dataclass(frozen=True)
class ContactRead:
    """The contact points one post carries, or the plain reason it carries none."""
    contacts: tuple[tuple[str, str], ...] = ()   # (kind, normalised contact): the fingerprint input, never stored
    reason: str | None = None


@dataclass
class LinkResult:
    matched: list[tuple[str, str]] = field(default_factory=list)   # (contact kind, fingerprint)
    unmatched_reason: str | None = None
    rows: int = 0


# Reading the contact out of a post ------------------------------------------------------------------------------------------

def find_contacts(body: bytes, content_type: str | None, fmap: extract.FieldMap | None, region: str | None = None) -> ContactRead:
    """The contact points of one post, in byte order and without repeats, or the reason there are none. Pure."""
    if fmap is None:
        return ContactRead(reason=NO_MAP)
    if not fmap.contact_paths:
        return ContactRead(reason=NO_CONTACT_PATH)
    try:
        values = extract.read_contact_values(body, content_type, fmap)
    except extract.Unreadable:  # loud-failure-exempt: the failure is the stored reason body_unreadable, and the caller raises its alarm
        return ContactRead(reason=BODY_UNREADABLE)
    if not values:
        return ContactRead(reason=CONTACT_NOT_SENT)
    found: list[tuple[str, str]] = []
    first_failure: str | None = None
    for hint, text in values:
        kind = hint if hint in ("phone", "email") else (detect_kind(text) if text is not None else "phone")
        try:
            if text is None:
                raise NormalizationError("not text")
            _, norm = normalize_contact(text, kind, region)
        except NormalizationError:  # loud-failure-exempt: the failure is the stored reason contact_unreadable_as_<kind>
            first_failure = first_failure or (UNREADABLE_EMAIL if kind == "email" else UNREADABLE_PHONE)
            continue
        if (kind, norm) not in found:
            found.append((kind, norm))
    if found:
        return ContactRead(contacts=tuple(found))
    return ContactRead(reason=first_failure)


# Bytes of a reading ---------------------------------------------------------------------------------------------------------

def _reading_bytes(state: str | None, values_ct_or_values) -> bytes | None:
    """The comparable bytes of a reading: the canonical list of its exact texts. None when there is no reading to compare."""
    if state is None or state in _NO_READING:
        return None
    return extract.values_json(values_ct_or_values)


def _open_values(blob, key: bytes | None, org, post_id, mv: int, name: str, encryption: str) -> bytes | None:
    if blob is None:
        return b"[]"
    from .tenancy import crypto as tc

    blob = bytes(blob)
    if encryption == ENC_NONE:
        return blob
    if key is None:
        return None
    return tc.decrypt_field(key, org, f"{post_id}:{mv}:{name}", COL_VALUES, blob)


def _seal(key: bytes | None, org, post_id, match_id, column: str, value: bytes | None) -> bytes | None:
    if value is None:
        return None
    if key is None:
        return value
    from .tenancy import crypto as tc

    return tc.encrypt_field(key, org, f"{post_id}:{match_id}", column, value)


def _lock(conn, org) -> None:
    conn.execute("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('consentvault.match:' || %s::text))", (str(org),))


def _source_of(blob, key, org, post_id, encryption: str) -> str | None:
    if blob is None:
        return None
    from .rawpost import COL_FACT
    from .tenancy import crypto as tc

    raw = bytes(blob) if encryption == ENC_NONE else (None if key is None else tc.decrypt_field(key, org, str(post_id), COL_FACT, bytes(blob)))
    return None if raw is None else json.loads(raw)


@dataclass
class _Prior:
    post_id: str
    order: tuple
    body_sha256: str
    consent: bytes | None
    wording: bytes | None
    source: str | None
    map_version: int | None
    data_key: bytes | None
    encryption: str


def _priors(writer, conn, org, rows: Iterable[dict]) -> list[_Prior]:
    from .tenancy.keys_protocol import WrappedKey

    out: list[_Prior] = []
    for r in rows:
        if r["post_id"] is None:
            continue
        key = None
        if r["post_key_wrapped"] is not None and r["encryption"] != ENC_NONE:
            key = writer.crypto.open_contact_key(org, WrappedKey(bytes(r["post_key_wrapped"]), r["key_version"]))
        mv, pid, enc = r["map_version"], r["post_id"], r["encryption"]
        consent = wording = None
        if mv is not None:
            if r["consent_state"] is not None and r["consent_state"] not in _NO_READING:
                consent = _open_values(r["consent_ct"], key, org, pid, mv, "consent", enc)
            if r["wording_state"] is not None and r["wording_state"] not in _NO_READING:
                wording = _open_values(r["wording_ct"], key, org, pid, mv, "wording", enc)
        out.append(_Prior(str(pid), (r["order_at"], r["seq"]), r["body_sha256"], consent, wording,
                          _source_of(r["source_ct"], key, org, pid, enc), mv, key, enc))
    return out


def _differs(a: bytes | None, b: bytes | None) -> bool | None:
    return None if a is None or b is None else a != b


# The match writer -----------------------------------------------------------------------------------------------------------

_INSERT = ("INSERT INTO consentvault.raw_post_match (org_id, post_id, match_id, map_version, status, unmatched_reason,"
           " contact_kind, contact_fp, record_id, previous_post_id, previous_same_source_post_id, consent_before_ct,"
           " consent_after_ct, changed, wording_changed, same_fingerprint_as_previous)"
           " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")


def _append(conn, org, post_id, mv, *, match_id=None, status, reason=None, kind=None, fp=None, record_id=None, previous=None, same_source=None,
            before=None, after=None, changed=None, wording_changed=None, same_body=None) -> None:
    conn.execute(_INSERT, (org, uuid.UUID(str(post_id)), match_id or uuid.uuid4(), mv, status, reason, kind, fp, record_id,
                           uuid.UUID(previous) if previous else None, uuid.UUID(same_source) if same_source else None,
                           before, after, changed, wording_changed, same_body))


def link_post(writer, conn: psycopg.Connection, enter: Callable | None, *, org: uuid.UUID | str, post: PostInfo,
              readings: Iterable[extract.Reading], contacts: ContactRead, map_version: int, source_id: uuid.UUID | str | None,
              data_key: bytes | None) -> LinkResult:
    """Append the link rows of one post: one per contact point, or one ``unmatched`` row with its reason. Runs inside the
    post's organisation on the capture path's own token (the one read it needs is ``match_lookup``). Raises ``LinkError`` when
    the rows cannot be written; the post is already stored and the repair run appends what is missing."""
    org = uuid.UUID(str(org))
    result = LinkResult()
    by_field = {r.field: r for r in readings}
    consent_now = _reading_bytes(by_field["consent"].state, by_field["consent"].values) if "consent" in by_field else None
    wording_now = _reading_bytes(by_field["wording"].state, by_field["wording"].values) if "wording" in by_field else None
    source = str(source_id) if source_id else None
    mine = (post.order_at, post.seq)
    try:
        ctx = enter(conn) if enter is not None else conn.transaction()
        with ctx:
            if not contacts.contacts:
                reason = contacts.reason or CONTACT_NOT_SENT
                _append(conn, org, post.post_id, map_version, status="unmatched", reason=reason)
                result.unmatched_reason, result.rows = reason, 1
                return result
            _lock(conn, org)
            for kind, norm in contacts.contacts:
                fp = writer.crypto.contact_fingerprint(org, kind, norm)
                rows = conn.execute("SELECT * FROM consentvault.match_lookup(%s)", (fp,)).fetchall()
                record_id = rows[0]["record_id"] if rows else None
                priors = [p for p in _priors(writer, conn, org, rows) if p.post_id != post.post_id]
                before_me = [p for p in priors if p.order < mine]
                after_me = [p for p in priors if p.order > mine]
                prev = before_me[-1] if before_me else None
                prev_same = next((p for p in reversed(before_me) if source is not None and p.source == source), None)
                match_id = uuid.uuid4()
                _append_match(conn, org, post, map_version, kind, fp, record_id, prev, prev_same, consent_now, wording_now,
                              data_key, match_id)
                result.matched.append((kind, fp))
                result.rows += 1
                # a post that arrived late (a queued request delivered after a later one) sits between two earlier ones: the
                # post that now follows it gets a new row that names it as its previous; the row it already has stays
                if after_me:
                    nxt = after_me[0]
                    if nxt.data_key is not None or nxt.encryption == ENC_NONE:
                        nxt_prev_same = None
                        if nxt.source is not None:
                            nxt_prev_same = next((p for p in reversed(before_me + [_Prior(
                                post.post_id, mine, post.body_sha256, consent_now, wording_now, source, map_version,
                                data_key, "")]) if p.source == nxt.source), None)
                        me_as_prior = _Prior(post.post_id, mine, post.body_sha256, consent_now, wording_now, source,
                                             map_version, data_key, "")
                        _append_match(conn, org, PostInfo(nxt.post_id, 0, nxt.order[0], nxt.body_sha256), nxt.map_version or 0,
                                      kind, fp, record_id, me_as_prior, nxt_prev_same, nxt.consent, nxt.wording, nxt.data_key,
                                      uuid.uuid4())
                        result.rows += 1
    except (psycopg.Error, ConsentVaultError) as exc:
        if isinstance(exc, LinkError):
            raise
        raise LinkError(f"the link rows of post {post.post_id} could not be written: {type(exc).__name__}") from exc
    return result


def _append_match(conn, org, post: PostInfo, mv: int, kind: str, fp: str, record_id, prev: "_Prior | None",
                  prev_same: "_Prior | None", consent_now: bytes | None, wording_now: bytes | None, key: bytes | None,
                  match_id: uuid.UUID) -> None:
    before = after = changed = wording_changed = same_body = None
    if prev is not None:
        same_body = prev.body_sha256 == post.body_sha256
        wording_changed = _differs(prev.wording, wording_now)
        changed = _differs(prev.consent, consent_now)
        if prev.consent is not None and consent_now is not None:
            before, after = prev.consent, consent_now
    _append(conn, org, post.post_id, mv, match_id=match_id, status="matched", kind=kind, fp=fp, record_id=record_id,
            previous=prev.post_id if prev else None, same_source=prev_same.post_id if prev_same else None,
            before=_seal(key, org, post.post_id, match_id, COL_BEFORE, before),
            after=_seal(key, org, post.post_id, match_id, COL_AFTER, after),
            changed=changed, wording_changed=wording_changed, same_body=same_body)


# Reading history ------------------------------------------------------------------------------------------------------------

def _texts(raw: bytes | None) -> list | None:
    return None if raw is None else json.loads(raw)


def _post_readings(conn, org, post_id, key, encryption: str) -> dict[int, dict[str, dict]]:
    """Every stored reading of a post by map version and field: ``{map_version: {field: {state, values, parsed}}}``."""
    out: dict[int, dict[str, dict]] = {}
    for r in conn.execute("SELECT map_version, field, state, values_ct, decision_time_parsed FROM consentvault.raw_post_field"
                          " WHERE org_id = %s AND post_id = %s ORDER BY map_version, field", (org, post_id)).fetchall():
        raw = _open_values(r["values_ct"], key, org, post_id, r["map_version"], r["field"], encryption)
        out.setdefault(r["map_version"], {})[r["field"]] = {"state": r["state"], "values": _texts(raw),
                                                           "parsed_derived": r["decision_time_parsed"]}
    return out


def _post_key(writer, conn, org, post_id, encryption: str):
    if encryption == ENC_NONE:
        return None, False
    key = writer.open_key(conn, org, post_id)
    return key, key is None


def _line(writer, conn, org, rows: list[dict], post: dict) -> dict:
    """One post's line: the reading made under the map in force when it arrived, the change from the previous post, and every
    later re-read listed apart. ``rows`` are the post's link rows for one contact point, oldest first."""
    from .tenancy import crypto as tc

    post_id = post["post_id"]
    key, erased = _post_key(writer, conn, org, post_id, post["encryption"])
    readings = _post_readings(conn, org, post_id, key, post["encryption"])
    versions = sorted(readings)
    arrival = versions[0] if versions else None
    first_version = min(r["map_version"] for r in rows)
    link = [r for r in rows if r["map_version"] == first_version][-1]   # the newest row of the version in force

    def field_of(version, name):
        f = (readings.get(version) or {}).get(name)
        return f if f is not None else {"state": "not_read", "values": None, "parsed_derived": None}

    line = {
        "post_id": str(post_id), "received_at": post["received_at"], "edge_received_at": post["edge_received_at"],
        "order_at": post["edge_received_at"] or post["received_at"], "intake": post["intake"],
        "contact_kind": link["contact_kind"], "record_id": link["record_id"],
        "map_version": arrival, "link_map_version": link["map_version"], "matched_at": link["matched_at"],
        "consent": field_of(arrival, "consent"), "decision_time": field_of(arrival, "decision_time"),
        "wording": field_of(arrival, "wording"), "wording_hash": field_of(arrival, "wording_hash"),
        "previous_post_id": str(link["previous_post_id"]) if link["previous_post_id"] else None,
        "previous_same_source_post_id": str(link["previous_same_source_post_id"]) if link["previous_same_source_post_id"] else None,
        "changed": link["changed"], "wording_changed": link["wording_changed"],
        "byte_identical_to": str(link["previous_post_id"]) if link["same_fingerprint_as_previous"] else None,
        "unusual_size": post["unusual_size"], "body_bytes": post["body_bytes"], "body_sha256": post["body_sha256"],
        "erased": erased, "changed_from": None, "rereads": [],
    }
    if link["changed"] and link["previous_post_id"]:
        before = None
        if link["consent_before_ct"] is not None:
            blob = bytes(link["consent_before_ct"])
            before = blob if key is None and post["encryption"] == ENC_NONE else (
                None if key is None else tc.decrypt_field(key, org, f"{post_id}:{link['match_id']}", COL_BEFORE, blob))
        prev = conn.execute("SELECT post_id, received_at, edge_received_at, encryption FROM consentvault.raw_post"
                            " WHERE org_id = %s AND post_id = %s", (org, link["previous_post_id"])).fetchone()
        prev_time = None
        if prev is not None:
            pkey, _ = _post_key(writer, conn, org, prev["post_id"], prev["encryption"])
            prev_readings = _post_readings(conn, org, prev["post_id"], pkey, prev["encryption"])
            if prev_readings:
                prev_time = (prev_readings[min(prev_readings)].get("decision_time") or {}).get("values")
        line["changed_from"] = {"post_id": str(link["previous_post_id"]), "consent_values": _texts(before),
                                "decision_time_values": prev_time, "received_at": prev["received_at"] if prev else None}
    for v in versions[1:]:
        line["rereads"].append({"map_version": v, "consent": field_of(v, "consent"), "decision_time": field_of(v, "decision_time"),
                                "wording": field_of(v, "wording"),
                                "matched_at": next((r["matched_at"] for r in reversed(rows) if r["map_version"] == v), None)})
    return line


def history_for_fp(writer, conn: psycopg.Connection, org: uuid.UUID | str, contact_fp: str) -> list[dict]:
    """Every post linked to one contact point, newest first by the earliest recorded arrival. Read-only; needs the evidence read
    scope. A post is a line once however many times it was re-read: later re-reads sit in ``rereads``."""
    org = uuid.UUID(str(org))
    rows = conn.execute("SELECT * FROM consentvault.raw_post_match WHERE org_id = %s AND contact_fp = %s AND status = 'matched'"
                        " ORDER BY map_version, matched_at, match_id", (org, contact_fp)).fetchall()
    by_post: dict[uuid.UUID, list[dict]] = {}
    for r in rows:
        by_post.setdefault(r["post_id"], []).append(r)
    lines = []
    for post_id, post_rows in by_post.items():
        post = conn.execute("SELECT * FROM consentvault.raw_post WHERE org_id = %s AND post_id = %s", (org, post_id)).fetchone()
        post_rows.sort(key=lambda r: (r["map_version"], r["matched_at"]))
        line = _line(writer, conn, org, post_rows, post)
        line["_order"] = (post["edge_received_at"] or post["received_at"], post["seq"])
        lines.append(line)
    lines.sort(key=lambda ln: ln["_order"], reverse=True)
    for ln in lines:
        ln.pop("_order")
    return lines


def person_fps(conn: psycopg.Connection, org: uuid.UUID | str, contact_fp: str | None = None, subject_fp: str | None = None) -> list[str]:
    """The contact points tied to one person by the existing person link (``record_index.subject_fp``), given the person's
    subject fingerprint or any one of their contact fingerprints. Read-only; an erased record is not listed."""
    org = uuid.UUID(str(org))
    if subject_fp is None:
        row = conn.execute("SELECT i.subject_fp FROM consentvault.record r JOIN consentvault.record_index i"
                           " ON i.org_id = r.org_id AND i.record_id = r.record_id"
                           " WHERE r.org_id = %s AND r.contact_fp = %s AND r.erased_at IS NULL", (org, contact_fp)).fetchone()
        subject_fp = row["subject_fp"] if row else None
    if subject_fp is None:
        return [contact_fp] if contact_fp else []
    return [r["contact_fp"] for r in conn.execute(
        "SELECT r.contact_fp FROM consentvault.record r JOIN consentvault.record_index i"
        " ON i.org_id = r.org_id AND i.record_id = r.record_id"
        " WHERE r.org_id = %s AND r.erased_at IS NULL AND i.subject_fp = %s ORDER BY r.first_recorded_at, r.record_id",
        (org, subject_fp)).fetchall()]


def person_history(writer, conn: psycopg.Connection, org: uuid.UUID | str, subject_fp: str) -> list[dict]:
    """The same lines for every contact point of one person, newest first, each carrying its ``contact_kind`` and ``record_id``."""
    lines: list[dict] = []
    for fp in person_fps(conn, org, subject_fp=subject_fp):
        lines += history_for_fp(writer, conn, org, fp)
    lines.sort(key=lambda ln: ln["order_at"], reverse=True)
    return lines


def unmatched_posts(conn: psycopg.Connection, org: uuid.UUID | str) -> list[dict]:
    """Posts whose newest link row is ``unmatched``, newest first, each with its plain reason. Read-only."""
    org = uuid.UUID(str(org))
    rows = conn.execute(
        "SELECT p.post_id, p.seq, p.received_at, p.edge_received_at, p.intake, p.body_bytes, p.body_sha256, p.unusual_size,"
        " m.map_version, m.unmatched_reason, m.matched_at FROM consentvault.raw_post_match m"
        " JOIN consentvault.raw_post p ON p.org_id = m.org_id AND p.post_id = m.post_id"
        " WHERE m.org_id = %s AND m.status = 'unmatched'"
        " AND m.map_version = (SELECT max(x.map_version) FROM consentvault.raw_post_match x WHERE x.org_id = m.org_id AND x.post_id = m.post_id)"
        " ORDER BY p.seq DESC", (org,)).fetchall()
    return [dict(r, reason_text=REASON_TEXT.get(r["unmatched_reason"], r["unmatched_reason"])) for r in rows]


def unmatched_count(conn: psycopg.Connection, org: uuid.UUID | str) -> int:
    """The number the dashboard shows: posts whose newest reading found no contact point."""
    return len(unmatched_posts(conn, org))
