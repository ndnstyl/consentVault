"""The capture step every intake runs: store the request, answer, then read it.

``store`` writes the raw post first (``rawpost.RawPostWriter``) and returns the stored post; nothing about the request is
checked before it. ``read_after_commit`` runs after the answer is given: it reads the stored bytes with the form's field
map (``extract``), appends the readings, and raises the capture alarms. None of it can change the answer already given or
remove the row; a failure of any step is logged and, where it can be, left as a fact beside the post.

The capture alarms (data-model.md section 7) name what an operator should look at; they never describe the sender.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Callable

import psycopg

from . import extract, safelog
from .alarms import AlarmWriteError, raise_operator_alarm
from .errors import ConsentVaultError
from .rawpost import Fact, RawPostWriter, RawRequest, StoredPost, StoreUnavailable

_log = safelog.get("consentvault.intake")

ALARM_FIELD_MAP_MISSING = "capture.field_map_missing"
ALARM_CONSENT_NOT_SENT = "capture.consent_not_sent"
ALARM_WORDING_NOT_SENT = "capture.wording_not_sent"
ALARM_BODY_UNREADABLE = "capture.body_unreadable"
ALARM_UNUSUAL_SIZE = "capture.unusual_size"
ALARM_UNMATCHED_POST = "capture.unmatched_post"
ALARM_LINK_FAILED = "capture.link_failed"
ALARM_QUEUE_PAST_DEADLINE = "capture.queue_past_deadline"
ALARM_VOLUME_SPIKE = "capture.volume_spike"
ALARM_CONTACT_CHECK_BEHIND = "capture.contact_check_behind"
ALARM_STORE_UNAVAILABLE = "capture.store_unavailable"
CAPTURE_ALARMS = (ALARM_FIELD_MAP_MISSING, ALARM_CONSENT_NOT_SENT, ALARM_WORDING_NOT_SENT, ALARM_BODY_UNREADABLE,
                  ALARM_UNUSUAL_SIZE, ALARM_UNMATCHED_POST, ALARM_LINK_FAILED, ALARM_QUEUE_PAST_DEADLINE,
                  ALARM_VOLUME_SPIKE, ALARM_CONTACT_CHECK_BEHIND, ALARM_STORE_UNAVAILABLE)


@dataclass
class AfterCommit:
    """What ``read_after_commit`` did: the readings made, the alarms raised, and each step that failed (class names only)."""
    readings: list = field(default_factory=list)
    alarms: list = field(default_factory=list)
    failures: list = field(default_factory=list)
    map_label: str | None = None


def store(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, req: RawRequest) -> StoredPost:
    """Write one raw post and nothing else. The only failure is ``StoreUnavailable``."""
    return writer.write(conn, enter, req)


def _alarm(conn, enter, name: str, post_id: str, error_class: str, request_id: str | None, out: AfterCommit) -> None:
    try:
        ctx = enter(conn) if enter is not None else conn.transaction()
        with ctx:
            raise_operator_alarm(conn, name=name, error_class=error_class, ref_kind="raw_post", ref_id=post_id,
                                 request_id=request_id)
        out.alarms.append(name)
    except (AlarmWriteError, ConsentVaultError, psycopg.Error) as exc:
        # the post is stored and its answer is given; the missing alarm is itself loud, never silent
        _log.critical("capture alarm NOT written; the operator must be told by another route", alarm=name,
                      request_id=request_id, error=type(exc).__name__)
        out.failures.append(f"alarm:{name}:{type(exc).__name__}")


def read_after_commit(writer: RawPostWriter, conn: psycopg.Connection, enter: Callable | None, stored: StoredPost,
                      req: RawRequest, *, source_id: uuid.UUID | str | None = None, request_id: str | None = None) -> AfterCommit:
    """Extraction and alarms for one stored post. Never raises: each failure is logged, counted and returned."""
    out = AfterCommit()
    org = uuid.UUID(stored.org_id)
    try:
        ctx = enter(conn) if enter is not None else conn.transaction()
        with ctx:
            fmap = extract.load_field_map(conn, source_id, req.intake)
    except (ConsentVaultError, psycopg.Error) as exc:
        _log.error("the field map could not be read; the post is stored and will be read again", request_id=request_id,
                   error=type(exc).__name__)
        out.failures.append(f"field_map:{type(exc).__name__}")
        return out
    out.map_label = fmap.label if fmap else None
    read_headers = req.read_headers if req.read_headers is not None else req.headers
    content_type = next((v for n, v in read_headers if n.lower() == "content-type"), None)
    out.readings = extract.read_fields(bytes(req.read_body if req.read_body is not None else req.body), content_type, fmap)
    try:
        extract.write_readings(conn, enter, org=org, post_id=stored.post_id, map_version=fmap.map_version if fmap else 0,
                               readings=out.readings, data_key=stored.data_key)
    except (ConsentVaultError, psycopg.Error) as exc:
        _log.error("the readings of a stored post could not be written; the post is stored", request_id=request_id,
                   error=type(exc).__name__)
        out.failures.append(f"readings:{type(exc).__name__}")
    by_field = {r.field: r for r in out.readings}
    if fmap is None:
        _alarm(conn, enter, ALARM_FIELD_MAP_MISSING, stored.post_id, "NoFieldMap", request_id, out)
    if any(r.state == extract.UNREADABLE for r in out.readings):
        _alarm(conn, enter, ALARM_BODY_UNREADABLE, stored.post_id, "BodyUnreadable", request_id, out)
    if fmap is not None and fmap.box_expected and by_field.get("consent") and by_field["consent"].state == extract.NOT_SENT \
            and req.kind == "post":
        _alarm(conn, enter, ALARM_CONSENT_NOT_SENT, stored.post_id, "ConsentNotSent", request_id, out)
    if fmap is not None and fmap.wording_path and by_field.get("wording") and by_field["wording"].state == extract.NOT_SENT \
            and req.kind == "post":
        _alarm(conn, enter, ALARM_WORDING_NOT_SENT, stored.post_id, "WordingNotSent", request_id, out)
    if stored.unusual_size:
        _alarm(conn, enter, ALARM_UNUSUAL_SIZE, stored.post_id, "UnusualSize", request_id, out)
    return out


__all__ = ["store", "read_after_commit", "AfterCommit", "StoreUnavailable", "Fact", "RawRequest", "CAPTURE_ALARMS"]
