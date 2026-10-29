"""RFC 3161 timestamp seals.

Each event's digest is sent to a timestamp authority; only the 32-byte digest leaves the host. The signed reply
is stored in the ``seal`` table together with the column list, the hash version, the authority URL and the
signing time. See docs/evidence-model.md for what a seal covers.

Requirements: an ``openssl`` binary whose ``ts`` command works. OpenSSL 3 is preferred. Set ``CONSENTVAULT_OPENSSL`` to
a binary path to choose one; otherwise ``openssl`` on PATH, the Homebrew prefix and common install paths are tried.
Set ``CONSENTVAULT_TSA_CAFILE`` to a PEM bundle holding the authority's root; otherwise the system bundle is used.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg

from .errors import ConsentVaultError
from .ledger import HASH_VERSIONS as LEDGER_HASH_VERSIONS, _canon_value, canonical_dumps

ENV_OPENSSL = "CONSENTVAULT_OPENSSL"
ENV_CAFILE = "CONSENTVAULT_TSA_CAFILE"

HTTP_TIMEOUT_S = 20
RETRIES = 3
BACKOFF_S = 1.0
OPENSSL_TIMEOUT_S = 30

# seal hash_version -> the event columns the seal digest covers. A column added to the event table later gets
# a new version here; seals already made keep verifying because each seal stores the columns it covered.
SEAL_HASH_VERSIONS: dict[int, tuple[str, ...]] = {
    1: tuple(LEDGER_HASH_VERSIONS[1]) + ("prev_hash", "row_hash"),
}

# A seal's signing time may not precede the event's received_at (whole seconds, the authority's resolution) and
# may not exceed it by more than this. Configurable per call; `seal_max_delay_seconds` in consentvault.toml.
DEFAULT_MAX_DELAY = timedelta(hours=24)

# An event still unsealed this long after the vault received it is a failure of verify-seals.
DEFAULT_UNSEALED_GRACE = timedelta(hours=1)


class SealError(ConsentVaultError):
    """Base class for seal failures."""


class OpensslNotFoundError(SealError):
    """No usable openssl binary was found."""


class TsaUnreachableError(SealError):
    """The timestamp authority could not be reached or answered with an HTTP error."""


class TsaRefusedError(SealError):
    """The authority answered but did not grant the request, or its reply does not verify."""


@dataclass(frozen=True)
class VerifyResult:
    event_id: str
    ok: bool
    reason: str
    seal_id: int | None = None
    gen_time: datetime | None = None


def current_hash_version() -> int:
    return max(SEAL_HASH_VERSIONS)


def _columns_for(hash_version: int) -> tuple[str, ...]:
    try:
        return SEAL_HASH_VERSIONS[hash_version]
    except KeyError:
        raise SealError(f"unknown seal hash_version {hash_version}") from None


def _digest_columns(row: dict, columns) -> bytes:
    missing = [c for c in columns if c not in row]
    if missing:
        raise SealError(f"the row has no column(s) {missing}; the column is part of the seal")
    payload = {c: _canon_value(row[c]) for c in columns}
    return hashlib.sha256(canonical_dumps(payload).encode("utf-8")).digest()


def seal_binds_event(row: dict, hash_version: int, columns, digest_hex: str) -> bool:
    """True only when ``columns`` are exactly the ones ``hash_version`` names and the digest recomputes."""
    if hash_version not in SEAL_HASH_VERSIONS or list(columns) != list(SEAL_HASH_VERSIONS[hash_version]):
        return False
    try:
        return _digest_columns(row, columns).hex() == digest_hex
    except SealError:
        return False


def digest(row: dict, hash_version: int) -> bytes:
    """sha256 over the canonical JSON of the columns that ``hash_version`` names."""
    return _digest_columns(row, _columns_for(hash_version))


def _brew_openssl() -> str | None:
    brew = shutil.which("brew")
    if not brew:
        return None
    try:
        r = subprocess.run([brew, "--prefix", "openssl"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return str(Path(r.stdout.strip()) / "bin" / "openssl")


def _is_real_openssl(path: str) -> bool:
    try:
        r = subprocess.run([path, "version"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and r.stdout.startswith("OpenSSL")


def _candidate_openssl() -> list[str]:
    raw = [shutil.which("openssl"), _brew_openssl(),
           "/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl",
           "/usr/local/bin/openssl", "/usr/bin/openssl"]
    seen: list[str] = []
    for c in raw:
        if c and c not in seen and os.access(c, os.X_OK):
            seen.append(c)
    return seen


@functools.lru_cache(maxsize=8)
def _resolve_openssl(override: str | None) -> str:
    if override:
        if not os.access(override, os.X_OK):
            raise OpensslNotFoundError(f"{ENV_OPENSSL}={override!r} is not an executable file")
        return override
    candidates = _candidate_openssl()
    for c in candidates:  # prefer a real OpenSSL over LibreSSL
        if _is_real_openssl(c):
            return c
    if candidates:
        return candidates[0]
    raise OpensslNotFoundError(f"no openssl binary found; install OpenSSL or set {ENV_OPENSSL} to its path")


def openssl_path() -> str:
    return _resolve_openssl(os.environ.get(ENV_OPENSSL))


def _trust_args() -> list[str]:
    ca = os.environ.get(ENV_CAFILE)
    if ca:
        if not Path(ca).is_file():
            raise SealError(f"{ENV_CAFILE}={ca!r} is not a file")
        return ["-CAfile", ca]
    sys_ca = ssl.get_default_verify_paths().cafile
    if sys_ca and Path(sys_ca).is_file():
        return ["-CAfile", sys_ca]
    return []


def _run(args: list[str], what: str) -> str:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=OPENSSL_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SealError(f"{what} could not run: {exc}") from exc
    if r.returncode != 0:
        raise SealError(f"{what} failed (exit {r.returncode}): {(r.stderr or r.stdout).strip()[:300]}")
    return (r.stdout or "") + (r.stderr or "")


_TIME_RE = re.compile(r"Time stamp:\s*(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?\s+(\d{4})")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _parse_gen_time(text: str) -> datetime:
    m = _TIME_RE.search(text)
    if not m or m.group(1) not in _MONTHS:
        raise TsaRefusedError("the timestamp reply carries no readable signing time")
    mon, day, hh, mm, ss, year = m.groups()
    return datetime(int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=timezone.utc)


def _verify_reply(ossl: str, tsr: Path, digest_hex: str, query: Path | None) -> None:
    args = [ossl, "ts", "-verify", "-in", str(tsr)]
    args += ["-queryfile", str(query)] if query else ["-digest", digest_hex]
    args += _trust_args()
    try:
        out = _run(args, "verifying the timestamp reply")
    except SealError as exc:
        raise TsaRefusedError(f"the timestamp reply does not verify: {exc}") from exc
    if "Verification: OK" not in out:
        raise TsaRefusedError("the timestamp reply did not verify: " + out.strip()[:200])


def _post(tsa_url: str, body: bytes, retries: int, delay: float) -> bytes:
    last: Exception | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            tsa_url, data=body, method="POST", headers={"Content-Type": "application/timestamp-query"})
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
                reply = resp.read()
                if resp.status == 200 and reply:
                    return reply
                last = urllib.error.URLError(f"HTTP {resp.status}, {len(reply)} bytes")
        except OSError as exc:
            last = exc
        if attempt < retries:
            time.sleep(delay * (2 ** attempt))
    raise TsaUnreachableError(
        f"timestamp authority {tsa_url} unreachable after {retries + 1} attempts "
        f"({type(last).__name__}: {str(last)[:150]})") from last


def stamp(digest_hex: str, tsa_url: str, *, backoff: float | None = None,
          retries: int = RETRIES) -> tuple[bytes, datetime]:
    """Ask the authority at ``tsa_url`` to sign a sha256 digest (64 hex chars).

    Returns (DER reply bytes, signing time in UTC). Raises TsaUnreachableError, TsaRefusedError or SealError.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", digest_hex):
        raise SealError("the digest to stamp must be 64 lowercase hex characters")
    if urllib.parse.urlparse(tsa_url).scheme not in ("http", "https"):
        raise SealError(f"the timestamp authority URL must be http or https: {tsa_url!r}")
    ossl = openssl_path()
    with tempfile.TemporaryDirectory(prefix="consentvault-seal-") as tmp:
        q = Path(tmp) / "req.tsq"
        _run([ossl, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", str(q)],
             "building the timestamp request")
        reply = _post(tsa_url, q.read_bytes(), retries, BACKOFF_S if backoff is None else backoff)
        tsr = Path(tmp) / "reply.tsr"
        tsr.write_bytes(reply)
        text = _run([ossl, "ts", "-reply", "-in", str(tsr), "-text"], "reading the timestamp reply")
        if "Status: Granted" not in text:
            raise TsaRefusedError("authority refused the timestamp request: " + text.strip()[:200])
        _verify_reply(ossl, tsr, digest_hex, q)
        return reply, _parse_gen_time(text)


def _fetch_row(conn: psycopg.Connection, event_id) -> dict | None:
    return conn.execute("SELECT * FROM consentvault.event WHERE event_id = %s", (event_id,)).fetchone()


def seal_pending(conn: psycopg.Connection, tsa_url: str, limit: int = 100, *,
                 backoff: float | None = None) -> list[str]:
    """Seal up to ``limit`` unsealed events, oldest first. One transaction per event.

    Returns the event ids sealed. A failing authority raises (earlier events stay sealed, the failing
    event writes nothing).
    """
    if limit < 1:
        raise SealError("limit must be at least 1")
    version = current_hash_version()
    pending = [r["event_id"] for r in conn.execute(
        "SELECT event_id FROM consentvault.unsealed_events ORDER BY seq LIMIT %s", (limit,))]
    sealed: list[str] = []
    for event_id in pending:
        row = _fetch_row(conn, event_id)
        if row is None:
            raise SealError(f"event {event_id} vanished while sealing")
        d = digest(row, version)
        token, gen_time = stamp(d.hex(), tsa_url, backoff=backoff)
        try:
            with conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(hashtext('consentvault.seal'), hashtext(%s))", (str(event_id),))
                already = conn.execute("SELECT 1 FROM consentvault.seal WHERE event_id = %s AND hash_version = %s",
                                       (event_id, version)).fetchone()
                if already:
                    continue
                conn.execute(
                    "INSERT INTO consentvault.seal (event_id, hash_version, columns, digest, tsa_url, token, gen_time) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (event_id, version, list(_columns_for(version)), d, tsa_url, token, gen_time))
        except psycopg.Error as exc:
            raise SealError(f"could not store the seal for event {event_id}: {exc}") from exc
        sealed.append(str(event_id))
    return sealed


def check_gen_window(gen_time: datetime, received_at: datetime, max_delay: timedelta) -> str | None:
    """None when the authority's signing time sits inside the allowed window after receipt, else the reason."""
    floor = received_at.astimezone(timezone.utc).replace(microsecond=0)
    if gen_time < floor:
        return (f"the seal's signing time {gen_time.isoformat()} precedes the event's received_at "
                f"{received_at.isoformat()}; a stamp cannot predate what it covers")
    if gen_time - received_at > max_delay:
        return (f"the seal's signing time {gen_time.isoformat()} is more than {max_delay} after the event's "
                f"received_at {received_at.isoformat()}")
    return None


def _token_gen_time(ossl: str, tsr: Path) -> datetime:
    text = _run([ossl, "ts", "-reply", "-in", str(tsr), "-text"], "reading the stored timestamp reply")
    return _parse_gen_time(text)


def _verify_one(conn: psycopg.Connection, seal: dict, row: dict, max_delay: timedelta) -> VerifyResult:
    eid = str(seal["event_id"])
    sid = seal["seal_id"]
    gen: datetime | None = None
    try:
        now = _digest_columns(row, list(seal["columns"]))
        if now != bytes(seal["digest"]):
            return VerifyResult(eid, False, "event digest differs from the sealed digest (digest mismatch)", sid)
        with tempfile.TemporaryDirectory(prefix="consentvault-seal-") as tmp:
            tsr = Path(tmp) / "seal.tsr"
            tsr.write_bytes(bytes(seal["token"]))
            ossl = openssl_path()
            _verify_reply(ossl, tsr, now.hex(), None)
            gen = _token_gen_time(ossl, tsr)
        if seal["gen_time"] is not None and seal["gen_time"] != gen:
            return VerifyResult(
                eid, False, f"the stored gen_time {seal['gen_time'].isoformat()} differs from the token's {gen.isoformat()}",
                sid, gen)
        bad = check_gen_window(gen, row["received_at"], max_delay)
        if bad:
            return VerifyResult(eid, False, bad, sid, gen)
    except SealError as exc:
        return VerifyResult(eid, False, str(exc), sid, gen)
    try:
        conn.execute("SELECT consentvault.mark_seal_verified(%s)", (sid,))
    except psycopg.Error as exc:
        return VerifyResult(eid, False, f"verified, but verified_at could not be recorded: {exc}", sid, gen)
    return VerifyResult(eid, True, "verified", sid, gen)


def verify(conn: psycopg.Connection, event_id, max_delay: timedelta = DEFAULT_MAX_DELAY) -> VerifyResult:
    """Re-digest the event's sealed columns and verify the stored token. Never raises for a bad seal."""
    seals = conn.execute("SELECT * FROM consentvault.seal WHERE event_id = %s ORDER BY seal_id", (event_id,)).fetchall()
    if not seals:
        return VerifyResult(str(event_id), False, "no seal for this event")
    row = _fetch_row(conn, event_id)
    if row is None:
        return VerifyResult(str(event_id), False, "sealed event is missing from the ledger")
    results = [_verify_one(conn, s, row, max_delay) for s in seals]
    bad = [r for r in results if not r.ok]
    if bad:
        return bad[0]
    last = results[-1]
    return VerifyResult(last.event_id, True, last.reason, last.seal_id, min(r.gen_time for r in results))


def verify_all(
    conn: psycopg.Connection,
    max_delay: timedelta = DEFAULT_MAX_DELAY,
    unsealed_grace: timedelta = DEFAULT_UNSEALED_GRACE,
) -> tuple[int, list[VerifyResult]]:
    """Verify every sealed event. Returns (events checked, failures).

    An event with no seal that the vault received more than ``unsealed_grace`` ago is a failure too.

    Besides each seal's own checks, the authority's signing times must not run backwards against ``seq``: a later
    event stamped earlier than an earlier event means a seal was swapped, re-ordered or made out of band.
    """
    rows = conn.execute(
        "SELECT DISTINCT e.event_id, e.seq FROM consentvault.seal s JOIN consentvault.event e USING (event_id) ORDER BY e.seq"
    ).fetchall()
    failures: list[VerifyResult] = []
    for u in conn.execute(
        "SELECT event_id, seq, received_at FROM consentvault.unsealed_events"
        " WHERE received_at < now() - %s ORDER BY seq", (unsealed_grace,)
    ).fetchall():
        failures.append(VerifyResult(
            str(u["event_id"]), False,
            f"event {u['seq']} has had no RFC 3161 timestamp seal since it was received at "
            f"{u['received_at'].isoformat()}, longer than the allowed {unsealed_grace}"))
    latest: datetime | None = None
    latest_seq: int | None = None
    for r in rows:
        res = verify(conn, r["event_id"], max_delay)
        if not res.ok:
            failures.append(res)
            continue
        if latest is not None and res.gen_time < latest:
            failures.append(VerifyResult(
                res.event_id, False,
                f"seal gen_time {res.gen_time.isoformat()} runs backwards against seq: event {r['seq']} was "
                f"stamped before event {latest_seq} ({latest.isoformat()})", res.seal_id, res.gen_time))
            continue
        latest, latest_seq = res.gen_time, r["seq"]
    return len(rows), failures
