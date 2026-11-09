"""RFC 3161 seals for history rows (item 29, gate 7): the same authority, token checks and gen-time window as the event and raw-post seals.

A row's digest is the SHA-256 of the canonical JSON of its columns, each as text, taken in name order. The seal names the exact column
list it digested and verification digests only those columns, so a column added to ``post_history`` later never touches an existing seal
(the consent-evidence rule).
"""

from __future__ import annotations

import hashlib
import hmac
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import psycopg

from .ledger import canonical_dumps
from .safelog import describe
from .seal import (DEFAULT_MAX_DELAY, DEFAULT_UNSEALED_GRACE, SealError, VerifyResult, _token_gen_time, _verify_reply,
                   check_gen_window, openssl_path, stamp)

HISTORY_SEAL_VERSION = 3


def _text(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return canonical_dumps([_text(v) for v in value])
    if isinstance(value, (dict,)):
        return canonical_dumps(value)
    return str(value)


def canon(row: dict) -> dict:
    return {k: _text(v) for k, v in sorted(row.items())}


def _digest(c: dict, columns) -> bytes:
    return hashlib.sha256(canonical_dumps({k: c[k] for k in columns}).encode("utf-8")).digest()


def seal_pending_history(conn: psycopg.Connection, tsa_url: str, limit: int = 100, *, backoff: float | None = None) -> list[str]:
    """Seal up to ``limit`` unsealed history rows of the entered organisation, oldest first. Returns the history event ids sealed."""
    if limit < 1:
        raise SealError("limit must be at least 1")
    pending = conn.execute(
        "SELECT h.* FROM consentvault.post_history h WHERE h.org_id = consentvault.current_org() AND NOT EXISTS"
        " (SELECT 1 FROM consentvault.post_history_seal s WHERE s.org_id = h.org_id AND s.history_seq = h.history_seq)"
        " ORDER BY h.history_seq LIMIT %s", (limit,)).fetchall()
    sealed: list[str] = []
    for row in pending:
        c = canon(row)
        columns = list(c)
        d = _digest(c, columns)
        token, gen_time = stamp(d.hex(), tsa_url, backoff=backoff)
        try:
            with conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(hashtext('consentvault.post_history_seal'), hashtext(%s))", (str(row["event_id"]),))
                if conn.execute("SELECT 1 FROM consentvault.post_history_seal WHERE org_id = consentvault.current_org()"
                                " AND history_seq = %s", (row["history_seq"],)).fetchone():
                    continue
                conn.execute("INSERT INTO consentvault.post_history_seal (history_seq, hash_version, columns_digested, digest, tsa_url, token, gen_time)"
                             " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                             (row["history_seq"], HISTORY_SEAL_VERSION, columns, d, tsa_url, token, gen_time))
        except psycopg.Error as exc:
            raise SealError(f"could not store the seal for history row {row['history_seq']}: {describe(exc)}") from exc
        sealed.append(str(row["event_id"]))
    return sealed


def _verify_one(conn: psycopg.Connection, s: dict, row: dict, max_delay: timedelta) -> VerifyResult:
    eid, sid, gen = str(row["event_id"]), str(s["seal_uuid"]), None
    c = canon(row)
    missing = [k for k in s["columns_digested"] if k not in c]
    if missing:
        return VerifyResult(eid, False, f"the seal names column(s) {missing} the history row no longer has", sid)
    try:
        now = _digest(c, s["columns_digested"])
        if not hmac.compare_digest(now, bytes(s["digest"])):
            return VerifyResult(eid, False, "history row digest differs from the sealed digest (digest mismatch)", sid)
        with tempfile.TemporaryDirectory(prefix="consentvault-seal-") as tmp:
            tsr = Path(tmp) / "seal.tsr"
            tsr.write_bytes(bytes(s["token"]))
            ossl = openssl_path()
            _verify_reply(ossl, tsr, now.hex(), None)
            gen = _token_gen_time(ossl, tsr)
        bad = check_gen_window(gen, row["received_at"], max_delay)
        if bad:
            return VerifyResult(eid, False, bad, sid, gen)
    except SealError as exc:  # loud-failure-exempt: the failure is the returned result, which verify_all_history reports as a failure
        return VerifyResult(eid, False, describe(exc), sid, gen)
    try:
        conn.execute("SELECT consentvault.mark_post_history_seal_verified(%s::uuid)", (sid,))
    except psycopg.Error as exc:  # loud-failure-exempt: the failure is the returned result, which verify_all_history reports as a failure
        return VerifyResult(eid, False, f"verified, but verified_at could not be recorded: {describe(exc)}", sid, gen)
    return VerifyResult(eid, True, "verified", sid, gen)


def verify_all_history(conn: psycopg.Connection, max_delay: timedelta = DEFAULT_MAX_DELAY,
                       unsealed_grace: timedelta = DEFAULT_UNSEALED_GRACE) -> tuple[int, list[VerifyResult], list[str]]:
    """(seals checked, failures, history event ids still unsealed inside the grace). A row unsealed past the grace is a failure."""
    failures: list[VerifyResult] = []
    waiting: list[str] = []
    for u in conn.execute(
        "SELECT h.event_id, h.history_seq, h.received_at, (h.received_at < now() - %s) AS late FROM consentvault.post_history h"
        " WHERE h.org_id = consentvault.current_org() AND NOT EXISTS (SELECT 1 FROM consentvault.post_history_seal s"
        " WHERE s.org_id = h.org_id AND s.history_seq = h.history_seq) ORDER BY h.history_seq", (unsealed_grace,)).fetchall():
        if u["late"]:
            failures.append(VerifyResult(str(u["event_id"]), False, f"history row {u['history_seq']} has had no RFC 3161 timestamp seal "
                                         f"since it was received at {u['received_at'].isoformat()}, longer than the allowed {unsealed_grace}"))
        else:
            waiting.append(str(u["event_id"]))
    checked = 0
    for r in conn.execute("SELECT DISTINCT h.* FROM consentvault.post_history_seal s JOIN consentvault.post_history h"
                          " ON h.org_id = s.org_id AND h.history_seq = s.history_seq WHERE s.org_id = consentvault.current_org()"
                          " ORDER BY h.history_seq").fetchall():
        for s in conn.execute("SELECT * FROM consentvault.post_history_seal WHERE org_id = consentvault.current_org() AND history_seq = %s"
                              " ORDER BY created_at, seal_uuid", (r["history_seq"],)).fetchall():
            checked += 1
            res = _verify_one(conn, s, r, max_delay)
            if not res.ok:
                failures.append(res)
    return checked, failures, waiting
