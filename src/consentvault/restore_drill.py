"""The restore drill (``consentvault restore-drill``): restore the latest backup into a scratch database, prove the copy, time
it, record it, and remove the copy.

One drill, in order:

1. checks its own production login is a member of ``consentvault_restore_drill`` (migration 0059): the only thing it
   writes to the production database is its drill record (``record_restore_drill``), and the wrong login could not;
2. restores the newest backup into a scratch database through a target: ``PgDumpTarget`` (self-host and tests: the
   newest ``consentvault-<UTC time>.dump`` in a folder, made with ``pg_dump --format=custom``) or
   ``providers.rds_restore.RdsSnapshotTarget`` (the cloud: the newest RDS snapshot of the vault's database, restored to
   the scratch instance ``cv-restore-drill``). The backup's own time is the restore point;
3. on the copy, as the operator console: ``restore.begin_restore`` (the gate must now answer 503:
   a pending restore run, what ``restore_pending()`` and the gate's guard read, is checked), then ``restore.reconcile`` for every organisation (the lifecycle ledger
   replayed, every evidence object written after the backup re-checked, the event chain with its anchors, the audit
   chain and every seal re-verified); after it the gate must be open again (no pending run);
4. checks the erasure coverage independently of the reconcile: every erasure whose intent has a commit in the lifecycle
   ledger is recorded as committed on the copy (``erasure_ledger_commit``), or is held behind a legal hold the reconcile
   named;
5. measures the time from the start of the restore to the end of the checks against the stated target
   (``CONSENTVAULT_RESTORE_DRILL_TARGET_SECONDS``, default 14400, four hours);
6. removes the copy in every outcome, and appends the drill record to the production database.

The drill passes only with no finding. Objects written after the backup that no key on the copy opens (a contact first
seen after the backup) are counted in the record, not a finding: the copy never serves, and a real restore asks an
operator to accept them (``runbooks/restore.md``). Every finding names its check, an organisation id and a count or a
check key, never a row of a tenant. A failed drill raises ``DrillFailed`` after the record is written; the command exits 3
and sends no heartbeat, and the schedule's exit alarm names it.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional, Protocol
from urllib.parse import urlsplit, urlunsplit

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from .errors import ConsentVaultError

GROUP = "consentvault_restore_drill"
OPERATOR_ID = "restore-drill"
ENV_TARGET_SECONDS = "CONSENTVAULT_RESTORE_DRILL_TARGET_SECONDS"
DEFAULT_TARGET_SECONDS = 4 * 3600
ACCEPT_NOTE = ("restore drill on a scratch copy that never serves: objects written after the backup that no key on the copy "
               "opens are counted in the drill record")
REPORT_LIMIT = 200  # findings kept in the record; the count is always whole


@dataclass(frozen=True)
class Backup:
    ref: str
    taken_at: datetime


@dataclass(frozen=True)
class Restored:
    """A restored copy: how to reach it as the operator console. ``set_role`` is entered after connecting (the cloud copy
    is reached as its master user, which first grants itself the console role on the copy only)."""
    backup: Backup
    dsn: str = field(repr=False)
    set_role: Optional[str] = None
    grant_role: bool = False


class ScratchTarget(Protocol):
    stale_removed: list[str]  # copies an earlier, killed drill left behind, removed before this one restored

    def restore_latest(self) -> Restored: ...
    def discard(self) -> None: ...


class DrillError(ConsentVaultError):
    """A drill step could not run (a setting, the scratch target). Raised before any record when nothing was restored."""


class DrillLoginRefused(ConsentVaultError):
    """The production login is not a member of the restore drill group: it could not record the drill."""


class DrillFailed(ConsentVaultError):
    """The drill ran and found at least one finding; ``record`` is what was written."""

    def __init__(self, message: str, record: dict) -> None:
        super().__init__(message)
        self.record = record


def target_seconds_from(env) -> int:
    raw = env.get(ENV_TARGET_SECONDS)
    if raw is None or raw == "":
        return DEFAULT_TARGET_SECONDS
    if not raw.strip().isdigit() or not 60 <= int(raw.strip()) <= 7 * 86400:
        raise DrillError(f"{ENV_TARGET_SECONDS} must be a whole number of seconds from 60 to 604800; got {raw!r}")
    return int(raw.strip())


def is_drill_login(conn) -> bool:
    row = conn.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = %s"
                       " AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')) AS member", (GROUP,)).fetchone()
    return bool(row["member"])


def require_drill_login(conn) -> None:
    from .job_logins import privileged

    why = privileged(conn)
    if why:
        raise DrillLoginRefused(f"{why}: the drill records with the drill login's one grant. Run this job as the restore "
                                "drill login", code='drill_login_privileged')
    if is_drill_login(conn):
        return
    who = conn.execute("SELECT current_user AS u").fetchone()["u"]
    raise DrillLoginRefused(f"login {who} is not a member of {GROUP}: it cannot record the drill. Run this job as the "
                            "restore drill login", code='drill_login_not_in_group')


def _reason(exc: BaseException) -> str:
    """The error's class and SQLSTATE only, never its text: a database error's detail can quote a row (an email address
    among them), and this lands in the drill record and the logs."""
    if isinstance(exc, psycopg.Error):
        return f"{type(exc).__name__} (SQLSTATE {exc.sqlstate})"
    cause = exc.__cause__
    if isinstance(cause, psycopg.Error):
        return f"{type(exc).__name__} from {type(cause).__name__} (SQLSTATE {cause.sqlstate})"
    return type(exc).__name__


_CHECK_KEY = re.compile(r"^(chain:event:\d+|chain:event|chain:audit:\d+|chain:audit|seal:[0-9a-f-]{36}|seal|ledger:\d+|"
                        r"events/[0-9A-Za-z._-]{1,200})$")
_CAUSE = re.compile(r"^[A-Za-z_ ]{1,80}$")


def _key(key) -> str:
    """A reconcile check key kept only in the shapes the reconcile writes (chain, seal, ledger sequence, object id)."""
    return key if isinstance(key, str) and _CHECK_KEY.match(key) else "unnamed"


def _cause(cause) -> str:
    """A reconcile cause cut to its own fixed name (the words before any colon); whatever followed is error text."""
    head = cause.split(":", 1)[0].strip() if isinstance(cause, str) else ""
    return head if _CAUSE.match(head) else "unnamed"


# ---- the self-host target: pg_dump archives in a folder -------------------------------------------------------------------
class PgDumpTarget:
    """The newest ``consentvault-YYYYMMDDTHHMMSSZ.dump`` in ``backup_dir`` (``pg_dump --format=custom``; the name carries the
    UTC time it was taken, the restore point), restored with ``pg_restore`` into a new scratch database on the server
    ``admin_dsn`` reaches (a superuser there: the vault's event triggers are restored with it). The copy is reached as
    the operator console login of ``console_dsn`` (its database name is swapped for the scratch one)."""

    NAME = re.compile(r"^consentvault-(\d{8}T\d{6}Z)\.dump$")

    def __init__(self, *, backup_dir: str | Path, admin_dsn: str, console_dsn: str, pg_restore: Optional[str] = None,
                 timeout_s: int = 6 * 3600, run=subprocess.run) -> None:
        self._dir, self._admin, self._console = Path(backup_dir), admin_dsn, console_dsn
        self._pg_restore = pg_restore or shutil.which("pg_restore")
        if not self._pg_restore:
            raise DrillError("pg_restore was not found on PATH and none was named; the drill cannot restore")
        self._timeout, self._run = timeout_s, run
        self._db: Optional[str] = None
        self._lock: Optional[psycopg.Connection] = None
        self.stale_removed: list[str] = []
        self.live_skipped: list[str] = []

    def latest(self) -> tuple[Path, Backup]:
        if not self._dir.is_dir():
            raise DrillError(f"the backup folder {self._dir} does not exist")
        found = sorted((m.group(1), p) for p in self._dir.iterdir() if (m := self.NAME.match(p.name)) and p.is_file())
        if not found:
            raise DrillError(f"no backup named consentvault-<UTC time>.dump in {self._dir}")
        stamp, path = found[-1]
        taken = datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        return path, Backup(path.name, taken)

    def _swap(self, dsn: str, db: str) -> str:
        u = urlsplit(dsn)
        if u.scheme not in ("postgresql", "postgres") or not u.path:
            raise DrillError("the drill's database addresses must be postgresql:// URLs naming a database")
        return urlunsplit((u.scheme, u.netloc, "/" + db, u.query, u.fragment))

    _LIBPQ_ENV = {"host": "PGHOST", "port": "PGPORT", "user": "PGUSER", "password": "PGPASSWORD", "sslmode": "PGSSLMODE",
                  "sslrootcert": "PGSSLROOTCERT", "passfile": "PGPASSFILE", "connect_timeout": "PGCONNECT_TIMEOUT"}

    def _libpq_env(self) -> dict:
        from psycopg.conninfo import conninfo_to_dict

        parts = conninfo_to_dict(self._admin)
        unknown = sorted(set(parts) - set(self._LIBPQ_ENV) - {"dbname"})
        if unknown:
            raise DrillError(f"the drill's admin address carries settings it cannot hand to pg_restore: {unknown}")
        env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        env.update({self._LIBPQ_ENV[k]: str(v) for k, v in parts.items() if k in self._LIBPQ_ENV})
        return env

    PREFIX = "cv_restore_drill_"

    # Each drill holds a session advisory lock named for its copy, on the admin database, from before the copy exists until
    # it is removed (the lock dies with the drill's session, so a killed drill releases it). A copy whose lock can be taken
    # has no live drill: it is stale. A copy whose lock is held belongs to a drill still running and is never touched.
    LOCK = "SELECT pg_advisory_lock(hashtextextended(%s, 0))"
    TRY_LOCK = "SELECT pg_try_advisory_lock(hashtextextended(%s, 0))"
    UNLOCK = "SELECT pg_advisory_unlock(hashtextextended(%s, 0))"

    def _drop_stale(self, su) -> None:
        """Copies an earlier drill left behind (it was killed before it could remove them) are dropped first, by name;
        a copy another running drill holds is left alone and named in ``live_skipped``."""
        for (name,) in su.execute("SELECT datname FROM pg_database WHERE starts_with(datname, %s) ORDER BY datname",
                                  (self.PREFIX,)).fetchall():
            if name == self._db:
                continue
            if not su.execute(self.TRY_LOCK, (name,)).fetchone()[0]:
                self.live_skipped.append(name)
                continue
            try:
                su.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
                self.stale_removed.append(name)
            finally:
                su.execute(self.UNLOCK, (name,))

    def _release(self) -> None:
        if self._lock is not None:
            lock, self._lock = self._lock, None
            lock.close()  # the session ends and its advisory lock with it

    def restore_latest(self) -> Restored:
        path, backup = self.latest()
        login = urlsplit(self._console).username
        if not login:
            raise DrillError("the console address names no login; the copy could not be opened to it alone")
        self._db = self.PREFIX + secrets.token_hex(6)
        self._lock = psycopg.connect(self._admin, autocommit=True)
        self._lock.execute(self.LOCK, (self._db,))
        with psycopg.connect(self._admin, autocommit=True) as su:
            self._drop_stale(su)
            su.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(self._db)))
            # Nobody but the drill reaches the copy: no login connects to it but the console login the drill acts as.
            su.execute(sql.SQL("REVOKE CONNECT, TEMPORARY ON DATABASE {} FROM PUBLIC").format(sql.Identifier(self._db)))
            su.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(self._db), sql.Identifier(login)))
        try:  # the connection travels in the child's environment, never on its command line (where ps shows it)
            done = self._run([self._pg_restore, "--exit-on-error", "--no-password", "--dbname", self._db, str(path)],
                             capture_output=True, text=True, timeout=self._timeout, env=self._libpq_env())
        except subprocess.TimeoutExpired as exc:
            raise DrillError(f"pg_restore did not finish within {self._timeout} seconds") from exc
        if done.returncode != 0:
            raise DrillError(f"pg_restore exited {done.returncode}: {(done.stderr or '').strip()[-500:]}")
        with psycopg.connect(self._swap(self._admin, self._db), autocommit=True) as su:  # the database's owner: the schema's
            owner = su.execute("SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace"
                               " WHERE nspname = 'consentvault'").fetchone()
            if owner is None:
                raise DrillError(f"the backup {backup.ref} restored no consentvault schema")
            su.execute(sql.SQL("ALTER DATABASE {} OWNER TO {}").format(sql.Identifier(self._db), sql.Identifier(owner[0])))
        return Restored(backup, self._swap(self._console, self._db))

    def discard(self) -> None:
        if self._db is None:
            self._release()
            return
        try:
            self._discard_own()
        finally:
            self._release()

    def _discard_own(self) -> None:
        with psycopg.connect(self._admin, autocommit=True) as su:
            su.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(self._db)))
            gone = su.execute("SELECT NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = %s)", (self._db,)).fetchone()[0]
        if not gone:
            raise DrillError(f"the scratch database {self._db} is still there after DROP DATABASE")
        self._db = None


# ---- the drill ----------------------------------------------------------------------------------------------------------------
def scratch_connector(restored: Restored) -> Callable[[], psycopg.Connection]:
    def connect() -> psycopg.Connection:
        try:
            conn = psycopg.connect(restored.dsn, autocommit=True, row_factory=dict_row)
        except psycopg.Error as exc:
            raise DrillError(f"the restored copy of {restored.backup.ref} could not be reached: {type(exc).__name__}") from exc
        if restored.set_role:
            role = sql.Identifier(restored.set_role)
            if restored.grant_role:
                conn.execute(sql.SQL("GRANT {} TO CURRENT_USER").format(role))
            conn.execute(sql.SQL("SET ROLE {}").format(role))
        return conn
    return connect


def _committed_erasures(entries: list[dict]) -> dict[str, int]:
    """erasure id -> intent seq, for every intent the ledger holds a matching commit for."""
    from .tenancy.restore import INTENT_KINDS

    intents = {e["seq"]: e for e in entries if e.get("kind") in INTENT_KINDS}
    out = {}
    for e in entries:
        if e.get("kind") == "erasure_commit":
            i = intents.get(e.get("intent_seq"))
            if i is not None and i.get("erasure_id") == e.get("erasure_id"):
                out[str(i["erasure_id"])] = i["seq"]
    return out


def _coverage(connect, token_key, ledger, report: dict) -> list[dict]:
    """Every committed erasure of the ledger is committed on the copy, or held behind a hold the reconcile named."""
    from .tenancy.erasure import operator_org
    from .tenancy.restore import RESTORE_SCOPES

    found = []
    for org, org_report in report.get("orgs", {}).items():
        want = _committed_erasures(ledger.entries(org))
        held = {str(h["erasure_id"]) for h in org_report.get("erasures_held", [])}
        if not want:
            continue
        with connect() as conn, operator_org(conn, token_key, org, scopes=RESTORE_SCOPES):
            have = {str(r["erasure_id"]) for r in conn.execute(
                "SELECT erasure_id FROM consentvault.erasure_ledger_commit WHERE org_id = (SELECT consentvault.current_org())"
                " AND erasure_id = ANY(%s::uuid[])", (list(want),))}
        missing = sorted(set(want) - have - held)
        if missing:
            found.append({"check": "erasure_not_covered", "org_id": org, "count": len(missing),
                          "erasure_ids": missing[:20]})
    return found


def _gate_closed(connect) -> bool:
    """The predicate the gate's restore guard and ``restore_pending()`` read: a restore run still pending."""
    with connect() as conn:
        return bool(conn.execute("SELECT EXISTS (SELECT 1 FROM consentvault.restore_run WHERE state = 'pending') AS p"
                                 ).fetchone()["p"])


def _summary(report: dict) -> dict:
    """The reconcile report reduced to counts per organisation (no object key beyond its check name)."""
    out = {}
    for org, r in report.get("orgs", {}).items():
        out[org] = {k: (len(v) if isinstance(v, list) else v) for k, v in r.items()}
    return out


def run_drill(target: ScratchTarget, *, record_connect: Callable[[], psycopg.Connection], token_key, crypto_for, store,
              ledger, inventory, target_seconds: int = DEFAULT_TARGET_SECONDS, request_id: str,
              clock: Callable[[], float] = time.monotonic, wall: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
              ) -> dict:
    """One drill (see the module text). ``crypto_for(connect)`` builds the tenant crypto over the copy (its wrapped
    secrets live there). Returns the record on a pass; raises ``DrillFailed`` with it on any finding,
    ``DrillLoginRefused`` before restoring anything when the production login is wrong."""
    from .tenancy import restore

    with record_connect() as conn:
        require_drill_login(conn)
    findings: list[dict] = []
    started_wall, t0 = wall(), clock()
    restored: Optional[Restored] = None
    report: dict = {}
    try:
        try:
            restored = target.restore_latest()
        except (ConsentVaultError, psycopg.Error, OSError) as exc:  # loud-failure-exempt: a failed restore is the drill's finding; it is recorded
            findings.append({"check": "restore_failed", "reason": _reason(exc)})
        if restored is not None:
            connect = scratch_connector(restored)
            try:
                with connect() as c:
                    restore.begin_restore(c, operator_id=OPERATOR_ID, request_id=request_id,
                                          restore_point=restored.backup.taken_at)
                if not _gate_closed(connect):
                    findings.append({"check": "gate_open_during_restore"})
                with connect() as c:
                    report = restore.reconcile(c, token_key=token_key, crypto=crypto_for(connect), store=store, ledger=ledger,
                                               inventory=inventory, operator_id=OPERATOR_ID, request_id=request_id,
                                               accept_unreadable=ACCEPT_NOTE)
            except restore.RestoreIncompleteError as exc:  # loud-failure-exempt: each failed check becomes a finding below
                report = exc.report
                for org, r in report.get("orgs", {}).items():
                    for f in r.get("failed_checks", [])[:REPORT_LIMIT]:
                        findings.append({"check": "reconcile", "org_id": org, "key": _key(f.get("key")),
                                         "cause": _cause(f.get("cause"))})
            except (ConsentVaultError, psycopg.Error, OSError) as exc:  # loud-failure-exempt: recorded as a finding; the drill fails
                findings.append({"check": "reconcile_could_not_run", "reason": _reason(exc)})
            if report and not any(f["check"] == "reconcile_could_not_run" for f in findings):
                try:
                    if _gate_closed(connect) and not any(f["check"] == "reconcile" for f in findings):
                        findings.append({"check": "gate_still_closed_after_reconcile"})
                    findings.extend(_coverage(connect, token_key, ledger, report))
                except (ConsentVaultError, psycopg.Error, OSError) as exc:  # loud-failure-exempt: recorded as a finding
                    findings.append({"check": "coverage_could_not_run", "reason": _reason(exc)})
        seconds = clock() - t0
    finally:
        try:
            target.discard()
        except (ConsentVaultError, psycopg.Error, OSError) as exc:  # loud-failure-exempt: recorded as a finding; the drill fails
            findings.append({"check": "scratch_not_removed", "reason": _reason(exc)})
    if restored is not None and seconds > target_seconds:
        findings.append({"check": "over_target", "seconds": round(seconds, 1), "target_seconds": target_seconds})
    if target.stale_removed:
        print(f"consentvault: restore drill removed {len(target.stale_removed)} copy(ies) an earlier drill left behind: "
              + ", ".join(target.stale_removed), file=sys.stderr)
    backup = restored.backup if restored is not None else None
    record = {
        "backup_ref": backup.ref if backup else "none",
        "backup_taken_at": (backup.taken_at if backup else started_wall).isoformat(),
        "started_at": started_wall.isoformat(),
        "seconds": round(seconds, 3),
        "target_seconds": target_seconds,
        "outcome": "failed" if findings else "passed",
        "orgs": len(report.get("orgs", {})),
        "report": {"findings": findings[:REPORT_LIMIT], "finding_count": len(findings),
                   "stale_copies_removed": list(target.stale_removed),
                   "unreadable_counted": sum(len(r.get("unreadable", [])) for r in report.get("orgs", {}).values()),
                   "orgs": _summary(report)},
    }
    finished_wall = started_wall + timedelta(seconds=seconds)
    with record_connect() as conn:
        record["drill_id"] = str(conn.execute(
            "SELECT consentvault.record_restore_drill(%s, %s, %s, %s, %s, %s, %s, %s::jsonb) AS id",
            (record["backup_ref"], record["backup_taken_at"], record["started_at"], finished_wall, target_seconds,
             record["outcome"], record["orgs"], json.dumps(record["report"], default=str))).fetchone()["id"])
    if findings:
        raise DrillFailed(f"the restore drill failed with {len(findings)} finding(s): "
                          + "; ".join(f["check"] + (f" (organisation {f['org_id']})" if f.get("org_id") else "")
                                      for f in findings[:20]), record)
    return record
