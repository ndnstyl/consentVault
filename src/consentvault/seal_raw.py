"""RFC 3161 seals for raw posts (data-model.md section 6): the same authority, token checks and gen-time window as the event
seals (``seal.py``), applied to the raw post chain.

A raw post's digest is the SHA-256 of the canonical JSON of the columns hash version 3 names (rawpost.canonical_row): the
row hash itself, recomputed here from the stored columns so a post changed after it was written is refused before it is
sealed and is a mismatch when it is verified. The seal names the exact column list it digested, and verification digests
only those columns, so a column added to the table later never touches an existing seal (consent-evidence rule).
"""

from __future__ import annotations

import hashlib
import hmac
import tempfile
from datetime import timedelta
from pathlib import Path

import psycopg

from .ledger import canonical_dumps
from .rawpost import HASH_VERSION, canonical_row, raw_post_row_hash
from .safelog import describe
from .seal import (DEFAULT_MAX_DELAY, DEFAULT_UNSEALED_GRACE, SealError, VerifyResult, _token_gen_time, _verify_reply,
                   check_gen_window, openssl_path, stamp)

RAW_SEAL_VERSION = HASH_VERSION


def _row_cts(row: dict) -> tuple[dict, dict]:
    ct = {"query_ct": bytes(row["query_ct"]), "headers_ct": bytes(row["headers_ct"]), "path_ct": bytes(row["path_ct"]),
          "body_ct": bytes(row["body_ct"]) if row["body_ct"] is not None else None}
    return canonical_row(row, ct), ct


def _digest(canon: dict, columns) -> bytes:
    return hashlib.sha256(canonical_dumps({c: canon[c] for c in columns}).encode("utf-8")).digest()


def digest_columns(row: dict) -> tuple[list[str], bytes]:
    """The column names a seal of this post covers and the digest over them, recomputed from the stored row."""
    canon, _ = _row_cts(row)
    return list(canon), _digest(canon, canon)


def seal_pending_raw(conn: psycopg.Connection, tsa_url: str, limit: int = 100, *, backoff: float | None = None) -> list[str]:
    """Seal up to ``limit`` unsealed raw posts of the entered organisation, oldest first, one transaction per post. A post whose
    stored columns no longer recompute to its row hash is not sealed: it raises (a seal would timestamp altered bytes)."""
    if limit < 1:
        raise SealError("limit must be at least 1")
    pending = conn.execute(
        "SELECT p.* FROM consentvault.raw_post p WHERE p.org_id = consentvault.current_org() AND NOT EXISTS"
        " (SELECT 1 FROM consentvault.raw_post_seal s WHERE s.org_id = p.org_id AND s.post_id = p.post_id)"
        " ORDER BY p.seq LIMIT %s", (limit,)).fetchall()
    sealed: list[str] = []
    for row in pending:
        if raw_post_row_hash(row, _row_cts(row)[1]) != row["row_hash"]:
            raise SealError(f"raw post {row['post_id']} no longer recomputes to its row hash; it is not sealed")
        columns, d = digest_columns(row)
        token, gen_time = stamp(d.hex(), tsa_url, backoff=backoff)
        try:
            with conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(hashtext('consentvault.raw_post_seal'), hashtext(%s))",
                             (str(row["post_id"]),))
                if conn.execute("SELECT 1 FROM consentvault.raw_post_seal WHERE org_id = consentvault.current_org()"
                                " AND post_id = %s", (row["post_id"],)).fetchone():
                    continue
                conn.execute(
                    "INSERT INTO consentvault.raw_post_seal (post_id, hash_version, columns, digest, tsa_url, token, gen_time)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (row["post_id"], RAW_SEAL_VERSION, columns, d, tsa_url, token, gen_time))
        except psycopg.Error as exc:
            raise SealError(f"could not store the seal for raw post {row['post_id']}: {describe(exc)}") from exc
        sealed.append(str(row["post_id"]))
    return sealed


def _verify_one(conn: psycopg.Connection, s: dict, row: dict, canon: dict, max_delay: timedelta) -> VerifyResult:
    post_id, sid, gen = str(row["post_id"]), str(s["seal_uuid"]), None
    missing = [c for c in s["columns"] if c not in canon]
    if missing:
        return VerifyResult(post_id, False, f"the seal names column(s) {missing} the post no longer has", sid)
    try:
        now = _digest(canon, s["columns"])  # only the columns the seal names: a column added later never touches it
        if not hmac.compare_digest(now, bytes(s["digest"])):
            return VerifyResult(post_id, False, "raw post digest differs from the sealed digest (digest mismatch)", sid)
        with tempfile.TemporaryDirectory(prefix="consentvault-seal-") as tmp:
            tsr = Path(tmp) / "seal.tsr"
            tsr.write_bytes(bytes(s["token"]))
            ossl = openssl_path()
            _verify_reply(ossl, tsr, now.hex(), None)
            gen = _token_gen_time(ossl, tsr)
        bad = check_gen_window(gen, row["received_at"], max_delay)
        if s["gen_time"] is not None and s["gen_time"] != gen:
            bad = f"the stored gen_time {s['gen_time'].isoformat()} differs from the token's {gen.isoformat()}"
        if bad:
            return VerifyResult(post_id, False, bad, sid, gen)
    except SealError as exc:  # loud-failure-exempt: the failure is the returned result, which verify_all_raw reports as a failure
        return VerifyResult(post_id, False, describe(exc), sid, gen)
    try:
        conn.execute("SELECT consentvault.mark_raw_post_seal_verified(%s::uuid)", (sid,))
    except psycopg.Error as exc:  # loud-failure-exempt: the failure is the returned result, which verify_all_raw reports as a failure
        return VerifyResult(post_id, False, f"verified, but verified_at could not be recorded: {describe(exc)}", sid, gen)
    return VerifyResult(post_id, True, "verified", sid, gen)


def verify_raw(conn: psycopg.Connection, post_id, max_delay: timedelta = DEFAULT_MAX_DELAY) -> VerifyResult:
    """Re-digest the post's sealed columns and verify the stored token. Never raises for a bad seal."""
    seals = conn.execute("SELECT * FROM consentvault.raw_post_seal WHERE org_id = consentvault.current_org() AND post_id = %s"
                         " ORDER BY created_at, seal_uuid", (post_id,)).fetchall()
    if not seals:
        return VerifyResult(str(post_id), False, "no seal for this raw post")
    row = conn.execute("SELECT * FROM consentvault.raw_post WHERE org_id = consentvault.current_org() AND post_id = %s",
                       (post_id,)).fetchone()
    if row is None:
        return VerifyResult(str(post_id), False, "sealed raw post is missing from the store")
    canon, _ = _row_cts(row)
    results = [_verify_one(conn, s, row, canon, max_delay) for s in seals]
    bad = [r for r in results if not r.ok]
    return bad[0] if bad else results[-1]


def verify_all_raw(conn: psycopg.Connection, max_delay: timedelta = DEFAULT_MAX_DELAY,
                   unsealed_grace: timedelta = DEFAULT_UNSEALED_GRACE) -> tuple[int, list[VerifyResult]]:
    """Verify every sealed raw post. A post with no seal that was received longer than ``unsealed_grace`` ago is a failure too."""
    failures: list[VerifyResult] = []
    for u in conn.execute(
        "SELECT p.post_id, p.seq, p.received_at FROM consentvault.raw_post p WHERE p.org_id = consentvault.current_org()"
        " AND p.received_at < now() - %s AND NOT EXISTS (SELECT 1 FROM consentvault.raw_post_seal s WHERE s.org_id = p.org_id"
        " AND s.post_id = p.post_id) ORDER BY p.seq", (unsealed_grace,)).fetchall():
        failures.append(VerifyResult(str(u["post_id"]), False,
                                     f"raw post {u['seq']} has had no RFC 3161 timestamp seal since it was received at "
                                     f"{u['received_at'].isoformat()}, longer than the allowed {unsealed_grace}"))
    rows = conn.execute("SELECT DISTINCT p.post_id, p.seq FROM consentvault.raw_post_seal s JOIN consentvault.raw_post p"
                        " ON p.org_id = s.org_id AND p.post_id = s.post_id WHERE s.org_id = consentvault.current_org()"
                        " ORDER BY p.seq").fetchall()
    for r in rows:
        res = verify_raw(conn, r["post_id"], max_delay)
        if not res.ok:
            failures.append(res)
    return len(rows), failures
