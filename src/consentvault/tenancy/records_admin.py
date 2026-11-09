"""The contact record list (records.md): list, summary, exact search, audited reveal, list export requests, and the
record-id form of the proof lookup.

Every function takes the request's ``Ctx`` (a connection already inside the caller's tenant, the caller, the request id).
The route table checks the role first; the functions below also keep a developer away from anything personal by
construction: a developer's list query never selects the mask or the display table.

* A list row is read from ``record`` and ``record_index`` (statuses, dates, sources); the masked contact and the person come
  from sealed columns opened with the organisation's display key, once per page. A key that cannot be used makes those fields
  null for the whole page and names them in ``partial``; a status never depends on a key.
* Reads that write an audit row (list, search, reveal, export) write it before the answer is built; when the row cannot be
  written the answer is ``audit_unavailable`` and nothing is returned.
* Nothing here logs or audits a contact point, a name or a company.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import psycopg
from psycopg.types.json import Jsonb

from .. import testing
from . import audit
from .admin_base import (ROLE_ADMIN, ROLE_VIEWER, ApiError, Ctx, body_dict, decode_cursor, encode_cursor, invalid, iso,
                         need_iso_time, need_list, paginate, parse_limit, want_enum)
from .errors import KeyProviderError

STATUSES = ("consent_record_found", "stop_on_record", "no_record")
CALL_CHANNELS = ("voice", "artificial_voice")
CONFIRMATIONS = ("sent", "delivered", "failed", "dead", "skipped", "none")
SOURCE_LIMIT = 20
SERIES_MAX_DAYS = 400
DEFAULT_WINDOW_DAYS = 30
REVEAL_MAX = 200
RATE_WINDOW_SECONDS = 600
RATE_DEFAULT = 30
TOTAL_TIMEOUT_MS = 2000
EXPORT_MAX_ROWS_DEFAULT = 250000
INLINE_BUILD_MAX = 2000  # a list this small is built right after its request commits; a larger one waits for the scheduled pass
E164 = re.compile(r"^\+[0-9]{7,15}$")
FILTER_KEYS = ("channel", "status", "purpose", "has_stop", "source_id", "brand_id", "date_field", "from", "to", "contact_kind",
               "state", "confirmation", "trial")
LIST_KEYS = FILTER_KEYS + ("sort", "limit", "cursor")
SUMMARY_KEYS = FILTER_KEYS + ("tz",)
SORTS = {"last_event_desc": ("i.last_event_at", True), "first_recorded_desc": ("r.first_recorded_at", True),
         "first_recorded_asc": ("r.first_recorded_at", False)}


def region_of(ctx: Ctx) -> str:
    """The phone region of the organization (records.md, phone region): its ``default_region``, ``US`` unless the operator set
    another."""
    row = ctx.conn.execute("SELECT default_region FROM consentvault.organization WHERE org_id = (SELECT consentvault.current_org())"
                           ).fetchone()
    if row is None:
        raise ApiError("not_found", "no such organization")
    return row["default_region"]


def now_of(ctx: Ctx) -> datetime:
    return datetime.fromtimestamp(ctx.now(), tz=timezone.utc)


def audited(ctx: Ctx, action: str, target_kind: str, target_id: Optional[str] = None, reason: Optional[str] = None,
            detail: Optional[dict] = None):
    """Write the audit row in this request's transaction and return its audit id; when it cannot be written the answer is
    ``audit_unavailable``."""
    try:
        return ctx.audit(action, target_kind, target_id, reason, detail)
    except (audit.AuditError, psycopg.Error) as exc:
        raise ApiError("audit_unavailable", "the action could not be recorded, so nothing was read or shown") from exc


def audited_now(ctx: Ctx, action: str, target_kind: str, target_id: Optional[str], reason: Optional[str],
                detail: Optional[dict]) -> None:
    """Write the audit row on its own connection and commit it at once, so it stands even if this request later fails."""
    from .tokens import org_transaction

    if ctx.connect is None or not ctx.token:
        raise ApiError("audit_unavailable", "the action could not be recorded, so nothing was read or shown")
    try:
        conn = ctx.connect()
        try:
            with org_transaction(conn, ctx.token):
                audit.append(conn, actor_kind=ctx.actor.kind, actor_id=ctx.actor.id, action=action, target_kind=target_kind,
                             target_id=target_id, reason=reason, request_id=ctx.request_id, detail=detail)
        finally:
            conn.close()
    except (audit.AuditError, psycopg.Error) as exc:
        raise ApiError("audit_unavailable", "the action could not be recorded, so nothing was read or shown") from exc


# ---- filters ----------------------------------------------------------------------------------------------------------------
def _text_list(value: Any, name: str) -> list[str]:
    items = list(value) if isinstance(value, (list, tuple)) else [value]
    if not items or any(not isinstance(v, str) or not v for v in items):
        raise invalid(**{name: "must be an id"})
    return items


def _flag(value: Any, name: str) -> bool:
    if value in (True, "true"):
        return True
    if value in (False, "false"):
        return False
    raise invalid(**{name: "must be true or false"})


def _org_channels(ctx: Ctx) -> set[str]:
    return {r["channel"] for r in ctx.conn.execute("SELECT channel FROM consentvault.channel WHERE org_id ="
                                                   " (SELECT consentvault.current_org())")}


def build_filters(ctx: Ctx, q: dict, allowed: tuple[str, ...]) -> tuple[list[str], list, dict]:
    """The WHERE fragments and parameters for the enumerated filters of records.md section 3, and the echo of what was asked
    (ids and enumerations only, safe to audit). Refuses any other parameter: a contact point is never a filter."""
    unknown = sorted(set(q) - set(allowed))
    if unknown:
        raise ApiError("validation_failed", f"unknown query parameters: {unknown}", {u: "not a filter" for u in unknown})
    q = {k: v for k, v in q.items() if v not in (None, "")}
    where = ["r.org_id = (SELECT consentvault.current_org())"]
    params: list = []
    echo: dict = {}

    channel = q.get("channel")
    if channel is not None:
        if channel != "call" and channel not in _org_channels(ctx):
            raise ApiError("invalid_channel", "that channel is not one this organization has")
        echo["channel"] = channel
    status = q.get("status")
    if status is not None:
        if status not in STATUSES:
            raise invalid(status="must be consent_record_found, stop_on_record or no_record")
        echo["status"] = status
    purpose = q.get("purpose")
    if purpose is not None:
        if not isinstance(purpose, str) or ctx.conn.execute(
                "SELECT 1 FROM consentvault.purpose WHERE org_id = (SELECT consentvault.current_org()) AND purpose = %s",
                (purpose,)).fetchone() is None:
            raise ApiError("UnknownPurposeError", "the purpose is not in this organization's configured list")
        echo["purpose"] = purpose
    if status is not None:
        chans = None if channel is None else (["voice", "artificial_voice"] if channel == "call" else [channel])
        sql = "EXISTS (SELECT 1 FROM jsonb_each(i.status_by_cell) c(ch, pv), jsonb_each_text(c.pv) p(pu, st) WHERE st = %s"
        params.append(status)
        if chans is not None:
            sql += " AND ch = ANY(%s)"
            params.append(chans)
        if purpose is not None:
            sql += " AND pu = %s"
            params.append(purpose)
        where.append(sql + ")")
    if "has_stop" in q:
        where.append("i.has_stop = %s")
        params.append(_flag(q["has_stop"], "has_stop"))
        echo["has_stop"] = params[-1]
    if "source_id" in q:
        ids = _text_list(q["source_id"], "source_id")
        if len(ids) > SOURCE_LIMIT:
            raise invalid(source_id=f"at most {SOURCE_LIMIT} sources")
        try:
            uids = sorted({uuid.UUID(v) for v in ids})
        except ValueError:
            raise ApiError("not_found", "no such source") from None
        have = ctx.conn.execute("SELECT count(*) AS n FROM consentvault.capture_source WHERE org_id ="
                                " (SELECT consentvault.current_org()) AND source_id = ANY(%s)", (uids,)).fetchone()["n"]
        if have != len(uids):
            raise ApiError("not_found", "no such source in this organization")
        where.append("i.source_ids && %s::uuid[]")
        params.append(uids)
        echo["source_id"] = [str(u) for u in uids]
    if "brand_id" in q:
        try:
            bid = uuid.UUID(str(q["brand_id"]))
        except ValueError:
            raise ApiError("not_found", "no such brand") from None
        if ctx.conn.execute("SELECT 1 FROM consentvault.brand WHERE org_id = (SELECT consentvault.current_org())"
                            " AND brand_id = %s", (bid,)).fetchone() is None:
            raise ApiError("not_found", "no such brand in this organization")
        where.append("%s = ANY(i.brand_ids)")
        params.append(bid)
        echo["brand_id"] = str(bid)
    date_field = want_enum(q.get("date_field", "first_recorded"), "date_field", ("first_recorded", "last_event"))
    col = "r.first_recorded_at" if date_field == "first_recorded" else "i.last_event_at"
    t_from = t_to = None
    if "from" in q:
        t_from = need_iso_time({"from": q["from"]}, "from")
        where.append(f"{col} >= %s")
        params.append(t_from)
        echo["from"] = iso(t_from)
    if "to" in q:
        t_to = need_iso_time({"to": q["to"]}, "to")
        where.append(f"{col} < %s")
        params.append(t_to)
        echo["to"] = iso(t_to)
    if t_from and t_to and t_from > t_to:
        raise invalid(**{"from": "later than to"})
    if "date_field" in q:
        echo["date_field"] = date_field
    if "contact_kind" in q:
        where.append("r.contact_kind = %s")
        params.append(want_enum(q["contact_kind"], "contact_kind", ("phone", "email")))
        echo["contact_kind"] = params[-1]
    state = want_enum(q.get("state", "active"), "state", ("active", "erased", "all"))
    if state != "all":
        where.append("r.erased_at IS NULL" if state == "active" else "r.erased_at IS NOT NULL")
    if "state" in q:
        echo["state"] = state
    if "confirmation" in q:
        conf = want_enum(q["confirmation"], "confirmation", CONFIRMATIONS)
        if conf == "none":
            where.append("i.last_confirmation IS NULL")
        else:
            where.append("i.last_confirmation ->> 'last_status' = %s")
            params.append(conf)
        echo["confirmation"] = conf
    trial = want_enum(q.get("trial", "include"), "trial", ("include", "exclude", "only"))
    if trial != "include":
        where.append("i.first_in_trial = %s")
        params.append(trial == "only")
    if "trial" in q:
        echo["trial"] = trial
    return where, params, echo


FROM = "FROM consentvault.record r JOIN consentvault.record_index i ON i.org_id = r.org_id AND i.record_id = r.record_id"


def _count(ctx: Ctx, where: list[str], params: list, switch: str) -> Optional[int]:
    """A count that gives up after two seconds or when its failed-reads switch is set: the answer is then None, never 0."""
    if switch in testing.fail_reads:
        return None
    prev = ctx.conn.execute("SELECT current_setting('statement_timeout') AS t").fetchone()["t"]
    try:
        with ctx.conn.transaction():
            ctx.conn.execute("SELECT set_config('statement_timeout', %s, true)", (str(TOTAL_TIMEOUT_MS),))
            n = ctx.conn.execute(f"SELECT count(*) AS n {FROM} WHERE {' AND '.join(where)}", params).fetchone()["n"]
            ctx.conn.execute("SELECT set_config('statement_timeout', %s, true)", (prev,))
            return n
    except psycopg.errors.QueryCanceled:  # loud-failure-exempt: a count that did not finish is null in the answer (records.md section 3), never 0
        return None


# ---- the list -----------------------------------------------------------------------------------------------------------------
def _select(role: str, k1: str) -> str:
    person = role in (ROLE_ADMIN, ROLE_VIEWER)
    return (
        "SELECT r.record_id, r.contact_kind, r.contact_fp, r.first_recorded_at, r.erased_at, i.last_event_at,"
        " i.first_source_id, i.source_ids, i.brand_ids, i.status_by_cell, i.has_stop, i.last_stop_at, i.first_in_trial,"
        " i.last_confirmation,"
        + (" i.mask_ct," if person else " NULL::bytea AS mask_ct,")
        + (" d.name_ct, d.company_ct," if person else " NULL::bytea AS name_ct, NULL::bytea AS company_ct,")
        + " (SELECT s.name FROM consentvault.capture_source s WHERE s.org_id = r.org_id AND s.source_id = i.first_source_id)"
          " AS first_source_name,"
          " CASE WHEN i.subject_fp IS NULL OR r.erased_at IS NOT NULL THEN 0 ELSE"
          " (SELECT count(*) FROM consentvault.record_index j JOIN consentvault.record rr ON rr.org_id = j.org_id"
          "   AND rr.record_id = j.record_id WHERE j.org_id = i.org_id AND j.subject_fp = i.subject_fp"
          "   AND j.record_id <> i.record_id AND rr.erased_at IS NULL) END AS linked,"
        + f" {k1} AS _k1, r.record_id::text AS _k2 {FROM}"
        + (" LEFT JOIN consentvault.record_display d ON d.org_id = r.org_id AND d.record_id = r.record_id" if person else ""))


def _open_page(ctx: Ctx) -> Optional[bytes]:
    """The display key for this page, or None when it cannot be used (the caller names the fields in ``partial``)."""
    try:
        return ctx.crypto.display_key(ctx.org_id())
    except KeyProviderError:  # loud-failure-exempt: the masked contact and person are null and named in partial (records.md section 3)
        return None


def _record_item(r: dict, role: str, key: Optional[bytes], org, partial: set, shown: list) -> dict:
    from . import crypto as tc
    from .errors import FieldCryptoError

    rid = str(r["record_id"])
    erased = r["erased_at"] is not None
    masked = None
    person = None
    if role in (ROLE_ADMIN, ROLE_VIEWER) and not erased:
        if r["mask_ct"] is None:
            partial.add("contact_mask")  # an event recorded while the display key could not be used; a later event fills it
        else:
            if key is None or "records.contact_mask" in testing.fail_reads:
                partial.add("contact_mask")
            else:
                try:
                    masked = tc.decrypt_text(key, org, rid, "mask_ct", bytes(r["mask_ct"]))
                except FieldCryptoError:  # loud-failure-exempt: the field is null and named in partial (records.md section 3)
                    partial.add("contact_mask")
        if r["name_ct"] is not None or r["company_ct"] is not None:
            if key is None or "records.person" in testing.fail_reads:
                partial.add("person")
            else:
                try:
                    person = {"name": tc.decrypt_text(key, org, rid, "name_ct", bytes(r["name_ct"])) if r["name_ct"] else None,
                              "company": tc.decrypt_text(key, org, rid, "company_ct", bytes(r["company_ct"]))
                              if r["company_ct"] else None}
                    shown.append(rid)
                except FieldCryptoError:  # loud-failure-exempt: the field is null and named in partial (records.md section 3)
                    partial.add("person")
    channels = {}
    for ch, by_purpose in (r["status_by_cell"] or {}).items():
        counts = {s: 0 for s in STATUSES}
        for st in by_purpose.values():
            counts[st] += 1
        channels[ch] = {"counts": counts,
                        "purposes": [{"purpose": p, "evidence_status": st} for p, st in sorted(by_purpose.items())]}
    sources = [str(s) for s in (r["source_ids"] or [])]
    conf = r["last_confirmation"]
    return {"record_id": rid, "contact_kind": r["contact_kind"],
            "contact": {"masked": masked, "fp_hint": r["contact_fp"][:8]}, "person": person,
            "state": "erased" if erased else "active", "first_recorded_at": iso(r["first_recorded_at"]),
            "last_event_at": iso(r["last_event_at"]),
            "first_source": ({"source_id": str(r["first_source_id"]), "name": r["first_source_name"]}
                             if r["first_source_id"] else None),
            "source_ids": sources[:5], "source_count": len(sources), "brand_ids": [str(b) for b in (r["brand_ids"] or [])],
            "channels": channels, "has_stop": r["has_stop"], "last_stop_at": iso(r["last_stop_at"]),
            "confirmation": ({"last_status": conf["last_status"], "channel": conf["channel"], "at": conf["at"]}
                             if conf else None),
            "recorded_during_trial": r["first_in_trial"], "linked_record_count": int(r["linked"])}


def _page(ctx: Ctx, endpoint: str, sql: str, params: list, desc: bool, limit: int, cursor: Optional[str]):
    """Keyset page in either direction over rows that expose ``_k1`` (timestamptz) and ``_k2`` (text). Answers
    (rows, next_cursor, prev_cursor)."""
    direction, k1, k2 = "after", None, None
    if cursor:
        v = decode_cursor(ctx.cursor_key, endpoint, cursor, ctx.now())
        if len(v) != 3 or v[0] not in ("after", "before"):
            raise ApiError("invalid_cursor", "the cursor expired or was not issued by this endpoint")
        direction, k1, k2 = v
    forward = desc if direction == "after" else not desc  # True: smaller keys come next
    order = "DESC" if forward else "ASC"
    where, args = "", list(params)
    if cursor:
        where = f" WHERE (_k1, _k2) {'<' if forward else '>'} (%s::timestamptz, %s::text)"
        args += [k1, k2]
    try:
        rows = ctx.conn.execute(f"SELECT * FROM ({sql}) q{where} ORDER BY _k1 {order}, _k2 {order} LIMIT %s",
                                args + [limit + 1]).fetchall()
    except (psycopg.errors.InvalidTextRepresentation, psycopg.errors.DatetimeFieldOverflow):
        raise ApiError("invalid_cursor", "the cursor expired or was not issued by this endpoint") from None
    more = len(rows) > limit
    rows = rows[:limit]
    if direction == "before":
        rows.reverse()

    def cur(kind: str, row: dict) -> str:
        return encode_cursor(ctx.cursor_key, endpoint, [kind, str(row["_k1"]), row["_k2"]], ctx.now())

    nxt = prv = None
    if rows:
        has_next = more if direction == "after" else bool(cursor)
        has_prev = bool(cursor) if direction == "after" else more
        nxt = cur("after", rows[-1]) if has_next else None
        prv = cur("before", rows[0]) if has_prev else None
    return rows, nxt, prv


def list_records(ctx: Ctx, q: dict) -> dict:
    role = ctx.actor.role
    where, params, echo = build_filters(ctx, q, LIST_KEYS)
    sort = want_enum(q.get("sort", "last_event_desc"), "sort", tuple(SORTS))
    k1, desc = SORTS[sort]
    limit = parse_limit(q.get("limit"))
    org = ctx.org_id()
    sql = _select(role, k1) + " WHERE " + " AND ".join(where)
    rows, nxt, prv = _page(ctx, f"GET /v1/records:{org}:{sort}", sql, params, desc, limit, q.get("cursor") or None)
    person_role = role in (ROLE_ADMIN, ROLE_VIEWER)
    named = [str(r["record_id"]) for r in rows if person_role and r["erased_at"] is None
             and (r["name_ct"] is not None or r["company_ct"] is not None)]
    total = _count(ctx, where, params, "records.total")
    # the audit row stands before any name is opened: the answer is built only after it is written
    audited(ctx, "records.listed", "records", None, None,
            {"filters": echo, "limit": limit, "count": len(rows), "person_shown_record_ids": named})
    partial: set = set()
    key = _open_page(ctx) if person_role and rows else None
    items = [_record_item(r, role, key, org, partial, []) for r in rows]
    return {"as_of": iso(now_of(ctx)), "items": items, "next_cursor": nxt, "prev_cursor": prv, "total": total,
            "partial": sorted(partial)}


# ---- summary ------------------------------------------------------------------------------------------------------------------
def summary(ctx: Ctx, q: dict) -> dict:
    where, params, _ = build_filters(ctx, q, SUMMARY_KEYS)
    tz_name = q.get("tz") or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        raise invalid(tz="must be an IANA time zone such as UTC or America/New_York") from None
    now = now_of(ctx)
    t_to = need_iso_time(q, "to") if q.get("to") else now
    if q.get("from"):
        t_from = need_iso_time(q, "from")
    else:  # the last DEFAULT_WINDOW_DAYS local days, the one holding `to` included, from the first instant of the first day
        first_day = (t_to - timedelta(microseconds=1)).astimezone(tz).date() - timedelta(days=DEFAULT_WINDOW_DAYS - 1)
        t_from = datetime.combine(first_day, datetime.min.time(), tzinfo=tz)
    if (t_to - t_from).days > SERIES_MAX_DAYS:
        raise invalid(**{"from": f"the series spans at most {SERIES_MAX_DAYS} days"})
    out: dict = {"as_of": iso(now), "tz": tz_name}
    partial: list[str] = []

    def read(name: str, fn):
        if "records.summary." + name in testing.fail_reads:
            partial.append(name)
            return None
        try:
            with ctx.conn.transaction():
                return fn()
        except psycopg.Error:  # loud-failure-exempt: the field is null and named in partial (records.md section 4)
            partial.append(name)
            return None

    def count(extra: str, args: list) -> int:
        return ctx.conn.execute(f"SELECT count(*) AS n {FROM} WHERE {' AND '.join(where)}{extra}",
                                params + args).fetchone()["n"]

    out["total"] = read("total", lambda: count("", []))
    out["with_stop"] = read("with_stop", lambda: count(" AND i.has_stop", []))
    out["new_in_range"] = read("new_in_range", lambda: count(" AND r.first_recorded_at >= %s AND r.first_recorded_at < %s",
                                                             [t_from, t_to]))

    def series():
        rows = ctx.conn.execute(
            f"SELECT (r.first_recorded_at AT TIME ZONE %s)::date AS d, count(*) AS n {FROM} WHERE {' AND '.join(where)}"
            " AND r.first_recorded_at >= %s AND r.first_recorded_at < %s GROUP BY 1", [tz_name] + params + [t_from, t_to]).fetchall()
        got = {r["d"]: r["n"] for r in rows}
        day, last = t_from.astimezone(tz).date(), (t_to - timedelta(microseconds=1)).astimezone(tz).date()
        days = []
        while day <= last:
            days.append({"date": day.isoformat(), "count": got.get(day, 0)})
            day += timedelta(days=1)
        return days
    out["new_per_day"] = read("new_per_day", series)

    def by_channel():
        rows = ctx.conn.execute(
            "SELECT c.ch AS channel,"
            " count(*) FILTER (WHERE s.st = 'consent_record_found') AS consent_record_found,"
            " count(*) FILTER (WHERE s.st = 'stop_on_record') AS stop_on_record,"
            " count(*) FILTER (WHERE s.st = 'no_record') AS no_record "
            f"{FROM}, jsonb_each(i.status_by_cell) c(ch, pv), LATERAL (SELECT CASE"
            "  WHEN bool_or(p.st = 'stop_on_record') THEN 'stop_on_record'"
            "  WHEN bool_or(p.st = 'consent_record_found') THEN 'consent_record_found' ELSE 'no_record' END AS st"
            "  FROM jsonb_each_text(c.pv) p(pu, st)) s "
            f"WHERE {' AND '.join(where)} GROUP BY c.ch", params).fetchall()
        got = {r["channel"]: r for r in rows}
        return [{"channel": ch, **{k: int(got[ch][k]) if ch in got else 0 for k in STATUSES}}
                for ch in sorted(_org_channels(ctx))]
    out["by_channel"] = read("by_channel", by_channel)

    def call_total():
        rows = ctx.conn.execute(
            "SELECT s.st AS st, count(*) AS n FROM (SELECT CASE"
            "  WHEN bool_or(p.st = 'stop_on_record') THEN 'stop_on_record'"
            "  WHEN bool_or(p.st = 'consent_record_found') THEN 'consent_record_found' ELSE 'no_record' END AS st "
            f"{FROM}, jsonb_each(i.status_by_cell) c(ch, pv), jsonb_each_text(c.pv) p(pu, st) "
            f"WHERE {' AND '.join(where)} AND c.ch = ANY(%s) GROUP BY r.record_id) s GROUP BY s.st",
            params + [list(CALL_CHANNELS)]).fetchall()
        got = {r["st"]: int(r["n"]) for r in rows}
        return {k: got.get(k, 0) for k in STATUSES}
    out["call"] = read("call", call_total)
    out["partial"] = [n for n in ("total", "with_stop", "new_in_range", "new_per_day", "by_channel", "call") if n in partial]
    return out


# ---- the one-contact lookups ---------------------------------------------------------------------------------------------------
def take_call(ctx: Ctx) -> None:
    """Take one search-or-reveal call from the member's window (30 per 10 minutes). The count lives in the database, so every
    process shares it, and is committed on its own connection at once, so a call that later fails still counted."""
    from .tokens import org_transaction

    if ctx.connect is None or not ctx.token:
        raise ApiError("service_unavailable", "the call limit could not be reached; nothing was read")
    limit = int(testing.override("records.reveal_rate_limit", RATE_DEFAULT))
    try:
        conn = ctx.connect()
        try:
            with org_transaction(conn, ctx.token):
                wait = conn.execute("SELECT consentvault.record_call_take(%s, %s, %s) AS wait",   # the database's clock
                                    (ctx.actor.id, limit, RATE_WINDOW_SECONDS)).fetchone()["wait"]
        finally:
            conn.close()
    except psycopg.Error as exc:
        raise ApiError("service_unavailable", "the call limit could not be reached; nothing was read") from exc
    if wait:
        err = ApiError("rate_limited", "too many searches and reveals; try again shortly")
        err.retry_after = int(wait)
        raise err


def contact_fingerprint(ctx: Ctx, contact: Any) -> tuple[str, str, str]:
    from .pipeline import normalize

    kind, norm = normalize(contact, region_of(ctx))
    try:
        return kind, norm, ctx.crypto.contact_fingerprint(ctx.org_id(), kind, norm)
    except KeyProviderError as exc:
        raise ApiError("key_unavailable", "the organization key could not be used; nothing was read") from exc


def search(ctx: Ctx, body: Any) -> dict:
    b = body_dict(body)
    if set(b) - {"contact"}:
        raise invalid(**{k: "not accepted" for k in set(b) - {"contact"}})
    take_call(ctx)
    _, _, fp = contact_fingerprint(ctx, b.get("contact"))
    role = ctx.actor.role
    rows = ctx.conn.execute(
        _select(role, "r.first_recorded_at") + " WHERE r.org_id = (SELECT consentvault.current_org()) AND r.contact_fp = %s"
        " ORDER BY (r.erased_at IS NOT NULL), r.first_seq DESC LIMIT 1", (fp,)).fetchall()
    # the audit row stands before the masked contact or any name is opened
    audited(ctx, "records.searched", "contact", fp[:8] if rows else None, None, {"found": bool(rows)})
    partial: set = set()
    org = ctx.org_id()
    key = _open_page(ctx) if rows else None
    items = [_record_item(r, role, key, org, partial, []) for r in rows]
    return {"items": items, "partial": sorted(partial)}


def _contact_of(ctx: Ctx, org, fp: str) -> str:
    """The normalised contact point of a fingerprint, from the newest event's sealed column (raises on an unusable key)."""
    from . import crypto as tc
    from .keys_protocol import WrappedKey

    key = ctx.conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (fp,)).fetchone()
    last = ctx.conn.execute("SELECT event_id, contact_ct FROM consentvault.post_history_all_events WHERE org_id ="
                            " (SELECT consentvault.current_org()) AND contact_fp = %s AND contact_ct IS NOT NULL ORDER BY seq DESC LIMIT 1",
                            (fp,)).fetchone()
    if key is None or last is None:
        raise KeyProviderError("no contact key or event is held for that fingerprint")
    dk = ctx.crypto.open_contact_key(org, WrappedKey(bytes(key["wrapped_key"]), key["key_version"]))
    return tc.decrypt_text(dk, org, str(last["event_id"]), "contact_norm", bytes(last["contact_ct"]))


def reveal(ctx: Ctx, body: Any) -> dict:
    from .errors import FieldCryptoError

    b = body_dict(body)
    if set(b) - {"record_ids", "reason"}:
        raise invalid(**{k: "not accepted" for k in set(b) - {"record_ids", "reason"}})
    raw = need_list(b, "record_ids", min_items=1, max_items=REVEAL_MAX)
    reason = b.get("reason")
    if reason is not None and (not isinstance(reason, str) or not 1 <= len(reason) <= 200):
        raise invalid(reason="1 to 200 characters")
    try:
        ids = list(dict.fromkeys(uuid.UUID(str(v)) for v in raw))
    except ValueError:
        raise invalid(record_ids="every id must be a record id") from None
    org = ctx.org_id()
    held = {r["record_id"]: r for r in ctx.conn.execute(
        "SELECT record_id, contact_fp, erased_at FROM consentvault.record WHERE org_id = (SELECT consentvault.current_org())"
        " AND record_id = ANY(%s)", (ids,))}
    if len(held) != len(ids):
        raise invalid(record_ids="one or more ids are not records of this organization")
    take_call(ctx)
    reveal_id = str(uuid.uuid4())
    audited_now(ctx, "records.reveal_requested", "contact_set", reveal_id, reason,
                {"requested": [str(i) for i in ids], "fp_hints": [held[i]["contact_fp"][:8] for i in ids]})
    items, revealed, missed = [], [], []
    for rid in ids:
        contact, cause = None, None
        if held[rid]["erased_at"] is not None:
            cause = "erased"
        else:
            try:
                contact = _contact_of(ctx, org, held[rid]["contact_fp"])
            except (KeyProviderError, FieldCryptoError):  # loud-failure-exempt: the item carries its cause and the revealed row lists it as not revealed
                cause = "key_unavailable"
        if cause:
            missed.append({"record_id": str(rid), "cause": cause})
        else:
            revealed.append(str(rid))
        items.append({"record_id": str(rid), "contact": contact, "cause": cause})
    done_id = audited(ctx, "records.revealed", "contact_set", reveal_id, reason, {"revealed": revealed, "not_revealed": missed})
    revealed_at = ctx.conn.execute("SELECT at FROM consentvault.audit_event WHERE audit_id = %s", (done_id,)).fetchone()["at"]
    if revealed:
        for alarm in ctx.conn.execute("SELECT * FROM consentvault.record_reveal_note(%s, %s)",   # the database's clock
                                      (ctx.actor.id, [uuid.UUID(r) for r in revealed])).fetchall():
            audited(ctx, "records.reveal_volume_alarm", "contact_set", reveal_id, None,
                    {"member_id": alarm["alarm_member"], "count": alarm["alarm_count"], "window": alarm["alarm_window"]})
    return {"reveal_id": reveal_id, "revealed_at": iso(revealed_at), "items": items}


# ---- list exports (the request half; the file is built by the export worker) ---------------------------------------------------------
def effective_status(r: dict, now: datetime) -> str:
    """A ready file is expired once its 24 hours are up, whether or not the worker has swept it."""
    if r["status"] == "ready" and r["expires_at"] is not None and r["expires_at"] <= now:
        return "expired"
    return r["status"]


def _export_item(r: dict, now: Optional[datetime] = None) -> dict:
    return {"export_id": str(r["export_id"]), "status": effective_status(r, now) if now else r["status"], "contact_form": r["contact_form"],
            "row_count": r["row_count"], "requested_by": r["requested_by"], "created_at": iso(r["created_at"]),
            "completed_at": iso(r["completed_at"]), "expires_at": iso(r["expires_at"]),
            "downloaded_at": iso(r["downloaded_at"]), "sha256": r["sha256"], "failed_cause": r["failed_cause"]}


def export_max_rows() -> int:
    import os

    default = int(os.environ.get("CONSENTVAULT_RECORDS_EXPORT_MAX_ROWS", EXPORT_MAX_ROWS_DEFAULT))
    return int(testing.override("records.export_max_rows", default))


def _cell(value: Any) -> str:
    """A CSV cell safe to open in a spreadsheet: a leading = + - @ tab or carriage return is prefixed with a quote, except an
    exact E.164 number (records.md section 7)."""
    text = "" if value is None else str(value)
    if text and text[0] in "=+-@\t\r" and not E164.fullmatch(text):
        return "'" + text
    return text


def _build_file(ctx: Ctx, rows: list, form: str, include_person: bool, filters: dict, export_id, requested_by: str,
                org_name: str, now: datetime) -> tuple[bytes, str, list[str]]:
    """The zip (records.csv, manifest.json, README.txt), the sha256 of records.csv, and the record ids it lists."""
    org = ctx.org_id()
    key = _open_page(ctx)
    channels = sorted(_org_channels(ctx))
    purposes = [r["purpose"] for r in ctx.conn.execute("SELECT purpose FROM consentvault.purpose WHERE org_id ="
                                                       " (SELECT consentvault.current_org()) ORDER BY purpose")]
    cells = [(c, p) for c in channels for p in purposes]
    head = (["record_id", "contact"] + (["name", "company"] if include_person else [])
            + ["contact_kind", "first_recorded_at", "last_event_at", "first_source", "sources", "has_stop", "last_stop_at"]
            + [f"{c}/{p}" for c, p in cells] + ["last_confirmation", "recorded_during_trial"])
    out = io.StringIO(newline="")
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(head)
    from . import crypto as tc
    for r in rows:
        rid = str(r["record_id"])
        erased = r["erased_at"] is not None
        if form == "fingerprint":
            contact = r["contact_fp"][:8]
        elif erased:
            contact = ""
        elif form == "full":
            contact = _contact_of(ctx, org, r["contact_fp"])
        else:
            if key is None:
                raise KeyProviderError("the display key could not be used")
            contact = tc.decrypt_text(key, org, rid, "mask_ct", bytes(r["mask_ct"])) if r["mask_ct"] is not None else ""
        name = company = ""
        if include_person and not erased and key is not None:
            name = tc.decrypt_text(key, org, rid, "name_ct", bytes(r["name_ct"])) if r["name_ct"] else ""
            company = tc.decrypt_text(key, org, rid, "company_ct", bytes(r["company_ct"])) if r["company_ct"] else ""
        by_cell = r["status_by_cell"] or {}
        conf = r["last_confirmation"]
        w.writerow([_cell(v) for v in (
            [rid, contact] + ([name, company] if include_person else [])
            + [r["contact_kind"], iso(r["first_recorded_at"]), iso(r["last_event_at"]), r["first_source_name"] or "",
               len(r["source_ids"] or []), r["has_stop"], iso(r["last_stop_at"]) or ""]
            + [by_cell.get(c, {}).get(p, "") for c, p in cells] + [conf["last_status"] if conf else "", r["first_in_trial"]])])
    csv_bytes = out.getvalue().encode("utf-8")
    sha = hashlib.sha256(csv_bytes).hexdigest()
    manifest = {"org_name": org_name, "filters": filters, "as_of": iso(now), "row_count": len(rows), "contact_form": form,
                "requested_by": requested_by, "sha256": sha}
    readme = ("This file lists the records ConsentVault holds for your organization on the date shown. "
              "It is not a legal determination.\n")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("records.csv", csv_bytes)
        z.writestr("manifest.json", json.dumps(manifest, sort_keys=True, indent=2))
        z.writestr("README.txt", readme)
    return buf.getvalue(), sha, [str(r["record_id"]) for r in rows]


def request_export(ctx: Ctx, body: Any) -> dict:
    from .admin_base import org_status

    b = body_dict(body)
    extra = set(b) - {"filters", "contact_form", "include_person", "reason"}
    if extra:
        raise invalid(**{k: "not accepted" for k in extra})
    form = want_enum(b.get("contact_form"), "contact_form", ("masked", "full", "fingerprint"))
    include_person = b.get("include_person", form != "fingerprint")
    if not isinstance(include_person, bool):
        raise invalid(include_person="must be true or false")
    if form == "fingerprint" and include_person:
        raise invalid(include_person="a fingerprint export cannot carry names")
    reason = b.get("reason")
    if reason is not None and (not isinstance(reason, str) or not 1 <= len(reason) <= 200):
        raise invalid(reason="1 to 200 characters")
    if form == "full" and reason is None:
        raise invalid(reason="required for a full export")
    filters = b.get("filters") or {}
    if not isinstance(filters, dict):
        raise invalid(filters="must be an object")
    status = org_status(ctx)
    if status == "suspended":
        raise ApiError("org_suspended", "list exports are paused while the organization is suspended")
    if status in ("offboarding", "closed"):
        raise ApiError("org_not_active", f"the organization is {status}; this action is refused")
    where, params, echo = build_filters(ctx, filters, FILTER_KEYS)
    estimate = _count(ctx, where, params, "records.total")
    if estimate is not None and estimate > export_max_rows():
        raise ApiError("export_too_large", "the list is over the export ceiling; narrow the filters",
                       {"count": estimate, "max": export_max_rows()})
    audited(ctx, "records.export_requested", "export", None, reason,
            {"filters": echo, "contact_form": form, "include_person": include_person})
    export_id = uuid.uuid4()
    try:
        with ctx.conn.transaction():
            ctx.conn.execute(
                "INSERT INTO consentvault.record_export (org_id, export_id, contact_form, include_person, filters, reason,"
                " requested_by, created_at, row_estimate) VALUES ((SELECT consentvault.current_org()), %s, %s, %s, %s, %s,"
                " %s, %s, %s)", (export_id, form, include_person, Jsonb(echo), reason, ctx.actor.id, now_of(ctx), estimate))
    except psycopg.errors.UniqueViolation:
        running = ctx.conn.execute("SELECT export_id FROM consentvault.record_export WHERE org_id ="
                                   " (SELECT consentvault.current_org()) AND status = 'building'").fetchone()
        raise ApiError("export_in_progress", "another list export of this organization is still building",
                       {"export_id": str(running["export_id"]) if running else None}) from None
    return {"export_id": str(export_id), "status": "building", "row_estimate": estimate}


def list_exports(ctx: Ctx, q: dict) -> dict:
    sql = ("SELECT e.*, e.created_at AS _k1, e.export_id::text AS _k2 FROM consentvault.record_export e"
           " WHERE e.org_id = (SELECT consentvault.current_org())")
    return paginate(ctx, endpoint="GET /v1/records/exports", select_sql=sql, params=[], key_cols=("_k1", "_k2"),
                    key_types=("timestamptz", "text"), descending=True, limit=q.get("limit"), cursor=q.get("cursor") or None,
                    shape=lambda r: _export_item(r, now_of(ctx)))


def get_export(ctx: Ctx, export_id: str, links) -> dict:
    """One export: the list fields, its progress while building, and the standing download link while it is good."""
    r = _export_row(ctx, export_id)
    out = _export_item(r, now_of(ctx))
    out["progress"] = {"done": r["progress_done"], "total": r["row_estimate"]} if r["status"] == "building" else None
    out["download_url"] = links.standing_url(ctx, r) if out["status"] == "ready" else None
    return out


def _export_row(ctx: Ctx, export_id: str) -> dict:
    try:
        eid = uuid.UUID(export_id)
    except ValueError:
        raise ApiError("not_found", "no such export") from None
    r = ctx.conn.execute("SELECT * FROM consentvault.record_export WHERE org_id = (SELECT consentvault.current_org())"
                         " AND export_id = %s", (eid,)).fetchone()
    if r is None:
        raise ApiError("not_found", "no such export")
    return r


# ---- proof by record id --------------------------------------------------------------------------------------------------------------
def record_for_proof(ctx: Ctx, record_id: Any) -> dict:
    """The record a ``record_id`` names in this organization (not_found otherwise), with its sealed columns."""
    try:
        rid = uuid.UUID(str(record_id))
    except ValueError:
        raise ApiError("not_found", "no such record") from None
    row = ctx.conn.execute(
        _select(ROLE_ADMIN, "r.first_recorded_at") + " WHERE r.org_id = (SELECT consentvault.current_org())"
        " AND r.record_id = %s", (rid,)).fetchone()
    if row is None:
        raise ApiError("not_found", "no such record")
    return row


def record_identity(ctx: Ctx, row: dict) -> dict:
    """The masked contact and the person of one record (nulls for an erased record or an unusable key)."""
    partial: set = set()
    key = _open_page(ctx) if row["erased_at"] is None else None
    item = _record_item(row, ctx.actor.role, key, ctx.org_id(), partial, [])
    return {"contact": item["contact"], "person": item["person"], "partial": sorted(partial)}
