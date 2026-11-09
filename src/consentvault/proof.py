"""Proof lookup: the full consent timeline for one person, read from every table."""

from __future__ import annotations

import hashlib
import re
from typing import Any

import psycopg

from . import dbclock
from .safelog import describe
from .errors import ConsentVaultError, NormalizationError
from .ledger import HASH_VERSIONS, _canon_value, canonical_dumps, content_sha256, subject_commitment
from .seal import seal_binds_event
from .normalize import normalize_contact

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

TABLES = ("event", "seal", "disclosure", "contact_log", "review", "chain_head")


def _clean(row: dict) -> dict:
    return {k: _canon_value(v) for k, v in row.items()}


def _resolve(query: str, region: str | None) -> tuple[str, dict]:
    q = (query or "").strip()
    if not q:
        raise ConsentVaultError("proof lookup needs a phone number, email or subject key")
    if "@" in q:
        kind, norm = normalize_contact(q, "email", region)
        return "contact", {"contact_kind": kind, "contact_norm": norm, "resolved_as": kind}
    if _HEX64.match(q.lower()):
        return "subject", {"subject_key": q.lower(), "resolved_as": "subject_key"}
    try:
        kind, norm = normalize_contact(q, "phone", region)
        return "contact", {"contact_kind": kind, "contact_norm": norm, "resolved_as": kind}
    except NormalizationError as exc:
        return "subject", {"subject_key": q, "resolved_as": "subject_key", "note": f"not read as a phone number: {describe(exc)}"}


def gather(conn: psycopg.Connection, query: str, region: str | None = None) -> tuple[dict, dict[str, bytes]]:
    """Return (proof structure, {seal file name: token bytes}). The structure holds no raw tokens."""
    mode, info = _resolve(query, region)
    if mode == "contact":
        rows = conn.execute(
            "SELECT * FROM consentvault.event WHERE contact_kind = %s AND contact_norm = %s ORDER BY seq",
            (info["contact_kind"], info["contact_norm"]),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM consentvault.event WHERE subject_key = %s ORDER BY seq", (info["subject_key"],)
        ).fetchall()

    contacts = {(r["contact_kind"], r["contact_norm"]) for r in rows}
    keys = {r["subject_key"] for r in rows}
    if mode == "contact":
        contacts.add((info["contact_kind"], info["contact_norm"]))
    if rows:
        by_seq = {r["seq"]: r for r in rows}
        while True:  # follow shared contact points and subject keys until no new event joins
            before = len(by_seq)
            for kind, norm in sorted(contacts):
                for r in conn.execute(
                    "SELECT * FROM consentvault.event WHERE contact_kind = %s AND contact_norm = %s", (kind, norm)
                ):
                    by_seq[r["seq"]] = r
            for r in conn.execute("SELECT * FROM consentvault.event WHERE subject_key = ANY(%s)", (sorted(keys),)):
                by_seq[r["seq"]] = r
            contacts |= {(r["contact_kind"], r["contact_norm"]) for r in by_seq.values()}
            keys |= {r["subject_key"] for r in by_seq.values()}
            if len(by_seq) == before:
                break
        rows = list(by_seq.values())
    rows.sort(key=lambda r: r["seq"])

    contact_list = sorted(contacts)
    event_ids = [r["event_id"] for r in rows]
    seals = conn.execute(
        "SELECT * FROM consentvault.seal WHERE event_id = ANY(%s) ORDER BY created_at, gen_time NULLS LAST, seal_uuid",
        (event_ids,)
    ).fetchall() if event_ids else []
    shas = sorted({r["disclosure_sha256"] for r in rows if r["disclosure_sha256"]})
    disclosures = conn.execute(
        "SELECT * FROM consentvault.disclosure WHERE sha256 = ANY(%s) ORDER BY sha256", (shas,)
    ).fetchall() if shas else []

    contact_log: list[dict] = []
    reviews: list[dict] = []
    for kind, norm in contact_list:
        contact_log += conn.execute(
            "SELECT * FROM consentvault.contact_log WHERE contact_kind = %s AND contact_norm = %s ORDER BY contacted_at, contact_log_id",
            (kind, norm),
        ).fetchall()
        reviews += conn.execute(
            "SELECT * FROM consentvault.review WHERE contact_kind = %s AND contact_norm = %s ORDER BY review_id",
            (kind, norm),
        ).fetchall()

    permissions: list[dict] = []
    for kind, norm in contact_list:
        permissions += conn.execute(
            "SELECT * FROM consentvault.current_permission WHERE contact_kind = %s AND contact_norm = %s"
            " ORDER BY channel, purpose",
            (kind, norm),
        ).fetchall()

    head = conn.execute("SELECT seq, row_hash FROM consentvault.event ORDER BY seq DESC LIMIT 1").fetchone()
    path: list[dict] = []
    anchors: list[dict] = []
    if rows:
        subject_seqs = {r["seq"] for r in rows}
        path = [
            {"seq": r["seq"], "prev_hash": r["prev_hash"], "row_hash": r["row_hash"],
             "contact_commit": r["contact_commit"], "subject_commit": subject_commitment(r["contact_salt"], r["subject_key"]),
             "content_sha256": (content_sha256(r, r["hash_version"]) if r["hash_version"] in HASH_VERSIONS
                                else None),
             "subject": r["seq"] in subject_seqs}
            for r in conn.execute("SELECT * FROM consentvault.event ORDER BY seq")
        ]
        anchors = [
            _clean(r)
            for r in conn.execute(
                "SELECT head_uuid::text AS head_id, seq, row_hash, sink, anchored_at FROM consentvault.chain_head"
                " ORDER BY anchored_at, seq"
            )
        ]

    seals_by_event: dict[Any, list[dict]] = {}
    tokens: dict[str, bytes] = {}
    row_by_id = {r["event_id"]: r for r in rows}
    for s in seals:
        ev = row_by_id[s["event_id"]]
        bucket = seals_by_event.setdefault(s["event_id"], [])
        name = f"{s['event_id']}.tsr" if not bucket else f"{s['event_id']}.{s['seal_uuid']}.tsr"
        token = bytes(s["token"])
        tokens[name] = token
        digest_hex = bytes(s["digest"]).hex()
        bucket.append({
            "seal_id": str(s["seal_uuid"]),
            "hash_version": s["hash_version"],
            "columns": list(s["columns"]),
            "digest": digest_hex,
            "digest_binds_event": seal_binds_event(ev, s["hash_version"], list(s["columns"]), digest_hex),
            "tsa_url": s["tsa_url"],
            "gen_time": _canon_value(s["gen_time"]),
            "verified_at": _canon_value(s["verified_at"]),
            "token_sha256": hashlib.sha256(token).hexdigest(),
            "file": f"seals/{name}",
        })

    timeline = []
    for r in rows:
        entry = _clean(r)
        entry["seals"] = seals_by_event.get(r["event_id"], [])
        entry["seal_status"] = "sealed" if entry["seals"] else "unsealed"
        entry["known_hash_version"] = r["hash_version"] in HASH_VERSIONS
        timeline.append(entry)

    found = bool(rows or contact_log or reviews)
    tables_read = {
        "event": len(rows), "seal": len(seals), "disclosure": len(disclosures),
        "contact_log": len(contact_log), "review": len(reviews), "chain_head": len(anchors),
    }
    if found:
        message = f"{len(rows)} consent event(s) found."
    else:
        message = (
            "No record: read every table (" + ", ".join(TABLES) + f") and nothing matches {query!r}."
            " The vault holds no consent, stop or contact history for this contact."
        )
    out_query = {"input": query, **info}
    result = {
        "query": out_query,
        "found": found,
        "message": message,
        "tables_read": tables_read,
        "contacts": [{"contact_kind": k, "contact_norm": n} for k, n in contact_list],
        "subject_keys": sorted(keys),
        "timeline": timeline,
        "permissions": [_clean(p) for p in permissions],
        "disclosures": [_clean(d) for d in disclosures],
        "contact_log": [_clean(c) for c in contact_log],
        "reviews": [_clean(v) for v in reviews],
        "chain": {
            "head": _clean(head) if head else None,
            "events": {str(r["event_id"]): {"seq": r["seq"], "row_hash": r["row_hash"]} for r in rows},
            "path": path,
            "anchors": anchors,
        },
    }
    return result, tokens


def lookup(conn: psycopg.Connection, query: str, region: str | None = None) -> dict:
    """Look up a phone, email or subject key. Returns the full proof structure."""
    return gather(conn, query, region)[0]


# Multi-tenant proof: everything on record for one contact in the entered organisation ------------------------------

PROOF_SECTIONS = ("timeline", "gate_decisions", "contact_log", "reviews")
DEFAULT_PAGE = 50
MAX_PAGE = 200


def _iso_z(t) -> str | None:
    from datetime import timezone

    return None if t is None else t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class _Section(Exception):
    """A section could not be read (carried to ``partial``)."""


def _page_args(page: Any) -> tuple[str | None, str | None, int]:
    from .tenancy.admin_base import ApiError

    if page is None:
        return None, None, DEFAULT_PAGE
    if not isinstance(page, dict) or page.get("section") not in PROOF_SECTIONS:
        raise ApiError("validation_failed", "page.section must be one of " + ", ".join(PROOF_SECTIONS),
                       {"page.section": "unknown section"})
    limit = page.get("limit", DEFAULT_PAGE)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_PAGE:
        raise ApiError("validation_failed", "page.limit must be 1 to 200", {"page.limit": "must be 1 to 200"})
    cursor = page.get("cursor")
    if cursor is not None and not isinstance(cursor, str):
        raise ApiError("invalid_cursor", "the cursor expired or was not issued by this endpoint")
    return page["section"], cursor, limit


def tenant_lookup(conn: psycopg.Connection, crypto, **kw) -> dict:
    """The proof answer for one contact, logged in the retrieval log before it is returned (gate 4): a read whose log row cannot be
    written raises and returns nothing."""
    from .retrieval import log_retrieval

    answer = _tenant_lookup(conn, crypto, **kw)
    log_retrieval(conn, answer)
    return answer


def _tenant_lookup(conn: psycopg.Connection, crypto, *, org, contact: Any = None, page: Any = None, region: str | None = None,
                  cursor_key: bytes, now: float | None = None, contact_fp: str | None = None,
                  contact_kind: str | None = None) -> dict:
    """The proof answer (contracts/proof-export.md) for one contact in the entered organisation.

    Shows the recorded evidence only; never a contact point, never a statement that a record
    establishes valid consent. A section that could not be read is named in ``partial`` and is ``null``.

    A caller that holds a record (records.md, proof by ``record_id``) passes ``contact_fp`` and ``contact_kind`` instead of
    ``contact``: the lookup then needs no contact point, so a record whose contact key was erased answers with the stops it
    still holds.
    """
    from .gate import NOTICE, tenant_facts
    from .tenancy.admin_base import ApiError, decode_cursor, encode_cursor
    from .tenancy.errors import KeyProviderError
    from .tenancy.pipeline import normalize

    section, cursor, limit = _page_args(page)
    if contact_fp is not None:
        kind, fp = contact_kind, contact_fp
    else:
        kind, norm = normalize(contact, region)
        try:
            fp = crypto.contact_fingerprint(org, kind, norm)
        except KeyProviderError as exc:
            raise ApiError("key_unavailable", "the organization key could not be used; nothing was read") from exc
    now_s = dbclock.epoch(conn) if now is None else now
    evaluated_at = _iso_z(dbclock.now(conn))
    after: list[str] | None = None
    if cursor is not None:
        values = decode_cursor(cursor_key, f"proof:{section}", cursor, now_s)
        if not values or values[0] != fp[:16]:
            raise ApiError("invalid_cursor", "the cursor expired or was not issued by this endpoint")
        after = values[1:]

    partial: list[str] = []

    def read(name: str, fn):
        try:
            with conn.transaction():
                return fn()
        except (psycopg.Error, _Section, KeyProviderError):
            partial.append(name)
            return None

    # every event of this person in this organisation (shared subject keys pull in their other contact points)
    def events():
        fps, sfps = {fp}, set()
        rows: dict = {}
        while True:
            before = len(rows)
            for r in conn.execute(
                    "SELECT * FROM consentvault.event WHERE org_id = consentvault.current_org()"
                    " AND (contact_fp = ANY(%s) OR subject_fp = ANY(%s))", (sorted(fps), sorted(sfps))):
                rows[("e", r["seq"])] = r
            for r in conn.execute("SELECT * FROM consentvault.history_events WHERE org_id = consentvault.current_org()"
                                  " AND contact_fp = ANY(%s)", (sorted(fps),)):
                rows[("h", r["seq"])] = r
            fps |= {r["contact_fp"] for r in rows.values() if r["contact_fp"]}
            sfps |= {r["subject_fp"] for r in rows.values() if r["subject_fp"]}
            if len(rows) == before:
                return [rows[k] for k in sorted(rows)], sorted(fps)

    got = read("timeline", events)
    ev_rows, fps = got if got is not None else ([], [fp])

    def paged(name: str, sql: str, params: tuple, key: tuple[str, str], asc: bool, shape):
        if section is not None and section != name:
            return "skip"

        def run():
            where, args = "", list(params)
            if after is not None and section == name:
                if len(after) != 2:
                    raise ApiError("invalid_cursor", "the cursor expired or was not issued by this endpoint")
                where = f" AND ({key[0]}, {key[1]}::text) {'>' if asc else '<'} (%s::timestamptz, %s)"
                args += after
            order = "ASC" if asc else "DESC"
            rows = conn.execute(f"{sql}{where} ORDER BY {key[0]} {order}, {key[1]}::text {order} LIMIT %s",
                                (*args, limit + 1)).fetchall()
            more = len(rows) > limit
            rows = rows[:limit]
            nxt = None
            if more:
                last = rows[-1]
                nxt = encode_cursor(cursor_key, f"proof:{name}",
                                    [fp[:16], last[key[0]].isoformat(), str(last[key[1]])], now_s)
            return {"items": [shape(r) for r in rows], "next_cursor": nxt}

        return read(name, run)

    trial = read("timeline", lambda: [
        (r["status"], r["from_at"]) for r in conn.execute(
            "SELECT status, from_at FROM consentvault.org_status_history WHERE org_id = consentvault.current_org()"
            " ORDER BY seq")]) or []

    def during_trial(at) -> bool:
        state = None
        for status, since in trial:
            if since <= at:
                state = status
        return state == "trial"

    ids = [r["event_id"] for r in ev_rows]
    seals = read("timeline", lambda: {
        str(r["event_id"]): (r["gen_time"] or r["created_at"]) for r in conn.execute(
            "SELECT event_id, min(coalesce(gen_time, created_at)) AS gen_time, min(created_at) AS created_at"
            "  FROM consentvault.seal WHERE org_id = consentvault.current_org() AND event_id = ANY(%s::uuid[])"
            " GROUP BY event_id", (ids,))}) or {}
    seals.update(read("timeline", lambda: {
        str(r["event_id"]): (r["gen_time"] or r["created_at"]) for r in conn.execute(
            "SELECT h.event_id, min(coalesce(s.gen_time, s.created_at)) AS gen_time, min(s.created_at) AS created_at"
            "  FROM consentvault.post_history_seal s JOIN consentvault.post_history h ON h.org_id = s.org_id AND h.history_seq = s.history_seq"
            " WHERE s.org_id = consentvault.current_org() AND h.event_id = ANY(%s::uuid[]) GROUP BY h.event_id", (ids,))}) or {})

    def tl_shape(r):
        sealed_at = seals.get(str(r["event_id"]))
        return {"event_id": str(r["event_id"]), "seq": r["seq"], "event_type": r["event_type"],
                "at": _iso_z(r["arrival_at"]), "channels": list(r["channels"]), "purposes": list(r["purposes"]),
                "source_id": str(r["source_id"]) if r["source_id"] else None,
                "brand_ids": [str(b) for b in (r["brand_ids"] or [])], "disclosure_sha256": r["disclosure_sha256"],
                "sealed": sealed_at is not None, "sealed_at": _iso_z(sealed_at),
                "recorded_during_trial": during_trial(r["arrival_at"])}

    timeline = paged("timeline", "SELECT * FROM (SELECT e.event_id, e.seq, e.event_type, e.channels, e.purposes, e.source_id, e.brand_ids,"
                     " e.disclosure_sha256, consentvault.arrival_at(e.org_id, e.event_id, e.received_at) AS arrival_at"
                     " FROM consentvault.event e WHERE e.org_id = consentvault.current_org() AND e.event_id = ANY(%s::uuid[])"
                     " UNION ALL SELECT h.event_id, h.seq, h.event_type, h.channels, h.purposes, h.source_id, h.brand_ids,"
                     " h.disclosure_sha256, h.arrival_at FROM consentvault.history_events h"
                     " WHERE h.org_id = consentvault.current_org() AND h.event_id = ANY(%s::uuid[])) arrived WHERE true",
                     ([str(i) for i in ids], [str(i) for i in ids]), ("arrival_at", "seq"), True,
                     tl_shape) if "timeline" not in partial else None
    gate_decisions = paged(
        "gate_decisions", "SELECT * FROM consentvault.gate_decision WHERE org_id = consentvault.current_org()"
        " AND contact_fp = ANY(%s)", (fps,), ("at", "decision_id"), False,
        lambda r: {"decision_id": str(r["decision_id"]), "at": _iso_z(r["at"]), "channel": r["channel"],
                   "purpose": r["purpose"], "evidence_status": r["evidence_status"]})
    contact_log = paged(
        "contact_log", "SELECT contact_log_uuid, contacted_at, channel, purpose, outcome, recorded_by"
        "  FROM consentvault.contact_log WHERE org_id = consentvault.current_org() AND contact_fp = ANY(%s)",
        (fps,), ("contacted_at", "contact_log_uuid"), False,
        lambda r: {"contact_log_id": str(r["contact_log_uuid"]), "at": _iso_z(r["contacted_at"]),
                   "channel": r["channel"], "purpose": r["purpose"], "outcome": r["outcome"],
                   "recorded_by": r["recorded_by"], "sealed": False})  # contact-log rows are not in the hash chain yet (core change C3)
    reviews = paged(
        "reviews", "SELECT review_uuid, created_at, kind, event_id FROM consentvault.review"
        " WHERE org_id = consentvault.current_org() AND contact_fp = ANY(%s)", (fps,), ("created_at", "review_uuid"),
        False, lambda r: {"review_id": str(r["review_uuid"]), "at": _iso_z(r["created_at"]),
                          "kind": "contact_control_unverified" if r["kind"] == "release" else r["kind"],
                          "event_id": str(r["event_id"]) if r["event_id"] else None})

    def total(sec) -> int:
        return len(sec["items"]) if isinstance(sec, dict) else 0

    found = bool(ev_rows) or any(total(x) for x in (gate_decisions, contact_log, reviews)) or bool(partial)
    if not found:
        return {"found": False, "evaluated_at": evaluated_at, "notice": NOTICE, "permissions": []}
    if section is not None:
        value = {"timeline": timeline, "gate_decisions": gate_decisions, "contact_log": contact_log,
                 "reviews": reviews}[section]
        return {"found": True, "evaluated_at": evaluated_at, "notice": NOTICE, section: value,
                "partial": sorted(set(partial))}

    def permissions():
        facts = tenant_facts(conn, kind, fp)
        pairs = conn.execute(
            "SELECT DISTINCT ON (channel, purpose) channel, purpose, allowed, reason, rule_set_version FROM consentvault.current_permission"
            " WHERE org_id = consentvault.current_org() AND contact_kind = %s AND contact_fp = ANY(%s)"
            " ORDER BY channel, purpose, allowed", (kind, fps)).fetchall()
        out = [{"channel": p["channel"], "purpose": p["purpose"], "status": facts.status, "allowed": p["allowed"], "reason": p["reason"],
                "rule_set_version": p["rule_set_version"],
                "basis_event_ids": [line["event_id"] for line in facts.history
                                    if p["channel"] in line["channels"] and (p["purpose"] in line["purposes"]
                                                                             or "*" in line["purposes"])]}
               for p in pairs]
        # a stop that exists only in history (after an organisation's cutover) is shown under the derived label and its rule set
        have = {o["channel"] for o in out}
        for stop in facts.stops:
            if stop["lifted_by_post_ids"]:
                continue
            for c in stop["channels"]:
                if c not in have:
                    have.add(c)
                    out.append({"channel": c, "purpose": "*", "status": facts.status, "basis_event_ids": [stop["event_id"]],
                                "derived": {"state": "stopped", "rule_set_version": "stopped-rule-0075"}})
        return out

    def disclosures():
        shas = sorted({r["disclosure_sha256"] for r in ev_rows if r["disclosure_sha256"]})
        return [{"sha256": d["sha256"], "label": d["label"], "version_label": d["version_label"]}
                for d in conn.execute("SELECT sha256, label, version_label FROM consentvault.disclosure"
                                      " WHERE org_id = consentvault.current_org() AND sha256 = ANY(%s)"
                                      " ORDER BY sha256", (shas,))]

    def doc_checks():
        if conn.execute("SELECT to_regclass('consentvault.doc_check_result') AS t").fetchone()["t"] is None:
            raise _Section("documentation-check results are not stored in this vault")
        return [{"event_id": str(r["event_id"]), "checklist_version": r["checklist_version"],
                 "present": list(r["present"] or []), "missing": list(r["missing"] or [])}
                for r in conn.execute(
                    "SELECT DISTINCT ON (event_id, checklist_version) event_id, checklist_version, present, missing"
                    " FROM consentvault.doc_check_result"
                    " WHERE org_id = consentvault.current_org() AND event_id = ANY(%s::uuid[])"
                    " ORDER BY event_id, checklist_version, checked_at DESC, check_id DESC", ([str(i) for i in ids],))]

    def chain():
        subject = {r["seq"] for r in ev_rows}
        all_rows = conn.execute("SELECT * FROM consentvault.event WHERE org_id = consentvault.current_org()"
                                " ORDER BY seq").fetchall()
        head = all_rows[-1] if all_rows else None
        return {
            "head": {"seq": head["seq"], "row_hash": head["row_hash"]} if head else None,
            "events": {str(r["event_id"]): {"seq": r["seq"], "row_hash": r["row_hash"]} for r in ev_rows},
            "path": [{"seq": r["seq"], "prev_hash": r["prev_hash"], "row_hash": r["row_hash"],
                      "contact_commit": r["contact_commit"], "subject_commit": r.get("subject_commit"),
                      "content_sha256": (content_sha256(r, r["hash_version"]) if r["hash_version"] in HASH_VERSIONS
                                         else None),
                      "subject": r["seq"] in subject} for r in all_rows],
            "anchors": [{"anchor_id": str(a["head_uuid"]), "seq": a["seq"], "row_hash": a["row_hash"],
                         "sink": a["sink"], "anchored_at": _iso_z(a["anchored_at"])}
                        for a in conn.execute(
                            "SELECT head_uuid, seq, row_hash, sink, anchored_at FROM consentvault.chain_head"
                            " WHERE org_id = consentvault.current_org() ORDER BY anchored_at, seq")],
        }

    return {
        "found": True,
        "evaluated_at": evaluated_at,
        "notice": NOTICE,
        "permissions_label": "derived: a reading of the history under a named rule set, not a record of what was sent",
        "permissions": read("permissions", permissions),
        "timeline": timeline,
        "disclosures": read("disclosures", disclosures),
        "gate_decisions": gate_decisions,
        "contact_log": contact_log,
        "reviews": reviews,
        "doc_check_results": read("doc_check_results", doc_checks),
        "chain": read("chain", chain),
        "partial": sorted(set(partial)),
    }
