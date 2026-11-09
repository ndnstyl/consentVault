"""The integrity jobs in multi-tenant mode: seal, verify-seals, verify-chain and anchor, once per organisation.

In multi mode a login with no tenant token sees no rows under row security, so a job run that way would find nothing,
exit clean and report success having checked nothing. These loops run as the dedicated integrity login (group
``consentvault_integrity``, migration 0048): they list the organisations (``dispatch_org_ids``), mint each one's
token just before working in it (``dispatch_org_token``, 300 seconds, so a slow organisation never outlives the next
one's token), and do the job inside that organisation (``org_transaction``).

Every organisation is attempted. One that fails does not stop the others; the run then raises ``IntegrityRunError``
naming each failed organisation by id with the reason (error class, sequence numbers, event ids and break kinds only,
never a contact or any other personal value), and the command exits non-zero, so no heartbeat is sent. The anchor job
skips an organisation whose ledger is empty, by id, and that is not a failure.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import timedelta
from typing import Any, Callable

import psycopg

from . import safelog
from .errors import ConsentVaultError
from .safelog import describe
from .tenancy.tokens import org_transaction

_log = safelog.get("consentvault.integrity")

INTEGRITY_GROUP = "consentvault_integrity"
JOB_SEAL, JOB_VERIFY_SEALS, JOB_VERIFY_CHAIN, JOB_ANCHOR = "seal", "verify_seals", "verify_chain", "anchor"


class IntegrityRunError(ConsentVaultError):
    """One or more organisations could not be completed. ``failures`` is [(org_id, reason)]; ``results`` the rest."""

    def __init__(self, job: str, failures: list[tuple[str, str]], results: Any) -> None:
        self.job, self.failures, self.results = job, failures, results
        super().__init__(f"{job} could not complete {len(failures)} organisation(s): "
                         + "; ".join(f"organisation {o}: {r}" for o, r in failures))


class _OrgFailure(Exception):
    """A per-organisation result that is a failure (breaks, failed seals). ``report_line`` is report data the job wrote from counts,
    sequence numbers, event ids and break kinds, never another error's text, so the report keeps it."""

    def __init__(self, detail: str) -> None:
        super().__init__("an organisation's check failed")
        self.report_line = detail


class MultiTenantRefused(ConsentVaultError):
    """Multi-tenant mode, and the login is not in the integrity group: without per-organisation tokens it would see no
    rows and report a clean run having checked nothing."""


def per_org_mode(conn: psycopg.Connection) -> bool:
    """True: run once per organisation (the integrity login). False: the single-company path (single mode).

    Raises ``MultiTenantRefused`` in multi-tenant mode for any other login. The mode is read the only way every login
    can: ``current_org()`` with no tenant token names the home organisation in single mode and nothing in multi mode.
    A login that cannot even ask is refused too (the mode is then unknown)."""
    if is_integrity_login(conn):
        return True
    try:
        org = conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"]
    except psycopg.Error as exc:
        raise MultiTenantRefused(
            f"cannot tell single from multi-tenant mode as login {_login(conn)} ({type(exc).__name__}); refusing to run: "
            f"in multi-tenant mode only a member of {INTEGRITY_GROUP} sees the ledger", code='integrity_mode_unknown') from exc
    if org is None:
        raise MultiTenantRefused(
            f"the vault is in multi-tenant mode and login {_login(conn)} is not a member of {INTEGRITY_GROUP}: it would "
            "see no rows and report a clean run having checked nothing. Run this job as the integrity jobs login", code='integrity_login_not_in_group')
    return False


def _login(conn: psycopg.Connection) -> str:
    return conn.execute("SELECT current_user AS u").fetchone()["u"]


def is_integrity_login(conn: psycopg.Connection) -> bool:
    """True when the connected login is a member of the integrity group (the multi-tenant job login)."""
    row = conn.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = %s"
                       " AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')) AS member",
                       (INTEGRITY_GROUP,)).fetchone()
    return bool(row["member"])


def _reason(exc: BaseException) -> str:
    # A database error's text can quote a row value (a unique-key detail); only its class and code are kept.
    if isinstance(exc, psycopg.Error):
        return f"{type(exc).__name__} (SQLSTATE {exc.sqlstate})"
    if isinstance(exc, _OrgFailure):
        return exc.report_line  # the job's own report: ids, counts and break kinds
    return f"{describe(exc)}"


def _org_ids(conn: psycopg.Connection, job: str) -> list:
    return [r["org"] for r in conn.execute("SELECT o AS org FROM consentvault.dispatch_org_ids(%s) o", (job,))]


def _each_org(conn: psycopg.Connection, job: str, work: Callable[[psycopg.Connection, uuid.UUID], Any]) -> dict:
    orgs = _org_ids(conn, job)
    results: dict[str, Any] = {}
    failures: list[tuple[str, str]] = []
    for org in orgs:
        try:
            token = conn.execute("SELECT consentvault.dispatch_org_token(%s, %s) AS t", (job, org)).fetchone()["t"]
            with org_transaction(conn, token):
                results[str(org)] = work(conn, org)
        except (ConsentVaultError, psycopg.Error, _OrgFailure, OSError, ValueError) as exc:  # loud-failure-exempt: recorded in failures; raised as IntegrityRunError after the remaining organisations ran
            failures.append((str(org), _reason(exc)))
    if failures:
        raise IntegrityRunError(job, failures, results)
    return results


OLDEST_UNSEALED_SQL = ("SELECT coalesce(extract(epoch FROM now() - min(received_at)), 0)::float8 AS age"
                       " FROM consentvault.unsealed_events WHERE org_id = consentvault.current_org()")


def seal_every_org(conn: psycopg.Connection, tsa_url: str, limit: int, *, backoff: float | None = None,
                   oldest_unsealed: dict | None = None) -> dict:
    """{org id: event ids sealed in this run}. ``oldest_unsealed`` (when given) receives {org id: seconds the oldest
    event still unsealed has waited}, read after the organisation's seals."""
    from .seal import seal_pending
    from .seal_history import seal_pending_history
    from .seal_raw import seal_pending_raw

    def one(c, org):
        done = (seal_pending(c, tsa_url, limit, backoff=backoff) + seal_pending_raw(c, tsa_url, limit, backoff=backoff)
                + seal_pending_history(c, tsa_url, limit, backoff=backoff))
        if oldest_unsealed is not None:
            oldest_unsealed[str(org)] = c.execute(OLDEST_UNSEALED_SQL).fetchone()["age"]
        return done
    return _each_org(conn, JOB_SEAL, one)


def verify_seals_every_org(conn: psycopg.Connection, max_delay: timedelta | None = None,
                           unsealed_grace: timedelta | None = None) -> dict:
    """{org id: seals checked}. Any failed or missing seal fails that organisation."""
    from . import seal

    md = max_delay if max_delay is not None else seal.DEFAULT_MAX_DELAY
    ug = unsealed_grace if unsealed_grace is not None else seal.DEFAULT_UNSEALED_GRACE

    def one(c, org):
        from .seal_history import verify_all_history
        from .seal_raw import verify_all_raw

        checked, failures = seal.verify_all(c, md, ug)
        raw_checked, raw_failures = verify_all_raw(c, md, ug)
        hist_checked, hist_failures, waiting = verify_all_history(c, md, ug)
        checked, failures = checked + raw_checked + hist_checked, failures + raw_failures + hist_failures
        if failures:
            raise _OrgFailure(f"{len(failures)} seal failure(s): "
                              + "; ".join(f"{f.event_id}: {f.reason}" for f in failures[:20]))
        return {"checked": checked, "unsealed_history": waiting} if waiting else checked
    return _each_org(conn, JOB_VERIFY_SEALS, one)


def _own_sink_records(sink_file: str, org: uuid.UUID, home: uuid.UUID, into: str) -> None:
    """Copy the sink records that belong to ``org`` (a record without org_id is the home organisation's) to ``into``."""
    keep = []
    with open(sink_file, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            owner = uuid.UUID(str(rec["org_id"])) if rec.get("org_id") else home
            if owner == org:
                keep.append(line if line.endswith("\n") else line + "\n")
    with open(into, "w", encoding="utf-8") as out:
        out.writelines(keep)


def verify_chain_every_org(conn: psycopg.Connection, *, sink_file: str | None = None, store=None, crypto=None) -> dict:
    """{org id: ledger rows checked}. A break fails that organisation. With ``sink_file`` each organisation is checked
    against its own records in the file sink (the sink holds every organisation's anchors). The raw post chain is checked
    too: every link and row hash, every fact digest, every anchor (database and sink), and, when ``store`` is given, every
    stored body read back and compared with its fingerprint."""
    from .ledger import verify_chain
    from .rawpost import verify_raw_anchors, verify_raw_bodies, verify_raw_chain

    def one(c, org):
        own = None
        try:
            if sink_file and os.path.exists(sink_file):
                home = c.execute("SELECT consentvault.home_org() AS h").fetchone()["h"]
                fd, own = tempfile.mkstemp(prefix="cv-sink-", suffix=".jsonl")
                os.close(fd)
                _own_sink_records(sink_file, org, home, own)
            breaks = verify_chain(c, sink_file=own if own else sink_file)
            raw = (verify_raw_chain(c) + verify_raw_anchors(c, sink_file=own if own else (
                sink_file if sink_file and os.path.exists(sink_file) else None)) + verify_raw_bodies(c, store, crypto))
        finally:
            if own:
                os.unlink(own)
        if breaks or raw:
            raise _OrgFailure(f"{len(breaks) + len(raw)} break(s): "
                              + "; ".join([f"seq {b.seq} {b.reason}" for b in breaks[:20]]
                                          + [f"raw post seq {b['seq']} {b['reason']}" for b in raw[:20]]))
        count = c.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = consentvault.current_org()"
                          ).fetchone()["n"] + c.execute("SELECT count(*) AS n FROM consentvault.raw_post WHERE org_id = "
                                                        "consentvault.current_org()").fetchone()["n"]
        cut = c.execute("SELECT EXISTS (SELECT 1 FROM consentvault.effect_watermark WHERE org_id = consentvault.current_org()) AS c").fetchone()["c"]
        missing = posts_without_history(c) if cut else []   # after cutover every stored post has a history row or a recorded reason
        if missing:   # gate 2: a stored post with no history row and no recorded reason is named, never counted past
            _log.error("stored posts have no history row and no recorded reason")
            return {"records": count, "posts_without_history": missing}
        if cut:   # after cutover the history head is part of the answer (item 35)
            head = c.execute("SELECT seq, row_hash FROM consentvault.history_head()").fetchone()
            return {"records": count, "history_head": head and head["row_hash"], "history_head_seq": head and head["seq"]}
        return count
    return _each_org(conn, JOB_VERIFY_CHAIN, one)


def posts_without_history(c: psycopg.Connection) -> list[str]:
    """Ids of the entered organisation's stored posts that have neither a history row nor a recorded reason (gate 2)."""
    return [str(r["post_id"]) for r in c.execute(
        "SELECT p.post_id FROM consentvault.raw_post p WHERE p.org_id = consentvault.current_org() AND p.kind = 'post'"
        " AND NOT EXISTS (SELECT 1 FROM consentvault.post_history h WHERE h.org_id = p.org_id AND h.post_id = p.post_id)"
        " AND NOT EXISTS (SELECT 1 FROM consentvault.projection_outcome o WHERE o.org_id = p.org_id AND o.post_id = p.post_id)"
        " ORDER BY p.seq").fetchall()]


def anchor_every_org(conn: psycopg.Connection, sink: str) -> dict:
    """{"anchored": {org id: anchor record}, "skipped_empty": [org ids]}. An empty ledger is skipped by id."""
    from .anchor import anchor

    skipped: list[str] = []

    def one(c, org):
        head = c.execute("SELECT seq FROM consentvault.ledger_head()").fetchone()
        raw_head = c.execute("SELECT seq FROM consentvault.raw_post_head()").fetchone()
        hist_head = c.execute("SELECT seq FROM consentvault.history_head() WHERE EXISTS (SELECT 1 FROM consentvault.effect_watermark"
                              " WHERE org_id = consentvault.current_org())").fetchone()
        if (head is None or head["seq"] is None) and raw_head is None and hist_head is None:
            skipped.append(str(org))
            return None
        return anchor(c, sink)
    try:
        done = _each_org(conn, JOB_ANCHOR, one)
    except IntegrityRunError as exc:
        exc.results = {"anchored": {o: r for o, r in exc.results.items() if r is not None}, "skipped_empty": skipped}
        raise
    return {"anchored": {o: r for o, r in done.items() if r is not None}, "skipped_empty": skipped}
