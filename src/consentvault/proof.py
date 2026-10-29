"""Proof lookup: the full consent timeline for one person, read from every table."""

from __future__ import annotations

import hashlib
import re
from typing import Any

import psycopg

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
        return "subject", {"subject_key": q, "resolved_as": "subject_key", "note": f"not read as a phone number: {exc}"}


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
        "SELECT * FROM consentvault.seal WHERE event_id = ANY(%s) ORDER BY seal_id", (event_ids,)
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
                "SELECT head_id, seq, row_hash, sink, anchored_at FROM consentvault.chain_head ORDER BY head_id"
            )
        ]

    seals_by_event: dict[Any, list[dict]] = {}
    tokens: dict[str, bytes] = {}
    row_by_id = {r["event_id"]: r for r in rows}
    for s in seals:
        ev = row_by_id[s["event_id"]]
        bucket = seals_by_event.setdefault(s["event_id"], [])
        name = f"{s['event_id']}.tsr" if not bucket else f"{s['event_id']}.{s['seal_id']}.tsr"
        token = bytes(s["token"])
        tokens[name] = token
        digest_hex = bytes(s["digest"]).hex()
        bucket.append({
            "seal_id": s["seal_id"],
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
