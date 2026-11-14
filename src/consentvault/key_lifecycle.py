"""The scheduled key-lifecycle job: organisation keys rotated on their schedule, and a census that proves it.

One run, as the key-lifecycle login (a member of ``consentvault_console``, the operator console's grants: the rotation
writes the key records, the audit chains and the operator alarms):

1. reads every organisation (``restore_org_ids``) and, inside each under a short operator token, its key versions and its
   status. An organisation whose active version has reached the rotation age (``CONSENTVAULT_KEY_ROTATION_DAYS``, default
   365, the yearly rotation of the security program) gets a rotation started through ``key_rotation.start_rotation``,
   with the reason naming the version and its age. Offboarding and closed organisations are skipped by id: their keys
   are being destroyed, never rotated;
2. runs every open rotation to the end through ``key_rotation.run_rotation_job`` (re-wrap, destroy or keep the old
   version for the ledger or the backups, sweep retained versions whose time has come). A rotation that fails there is
   recorded blocked and alarmed by that job; this run names it as a failure;
3. reads the census again in every organisation: any active version still past the rotation age, and any version that is
   no longer active (and not destroyed) with anything still wrapped under it (``key_version_census``), by kind.

A start that fails, a rotation that fails, a key past its age or a census row on an old version fails the run with
``KeyLifecycleError``; the command then exits 3 and sends no heartbeat, and its two metrics (``KeysPastRotationAge``,
``KeysOnOldVersion``) carry the counts for the alarms. A clean run writes both as zeros. Every organisation is attempted
before the run fails. The report names organisation ids, version numbers, kinds and counts only.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Mapping, Optional

import psycopg

from .safelog import describe
from .errors import ConsentVaultError

CONSOLE_GROUP = "consentvault_console"
OPERATOR_ID = "key-lifecycle-job"
ENV_ROTATION_DAYS = "CONSENTVAULT_KEY_ROTATION_DAYS"
DEFAULT_ROTATION_DAYS = 365
MAX_ROTATION_DAYS = 3650
SKIPPED_STATUSES = ("offboarding", "closed")
# What a step in one organisation can raise; anything else is a defect and stops the run at once.
_STEP_ERRORS = (ConsentVaultError, psycopg.Error, OSError)
DAY_SECONDS = 86400


class KeyLifecycleError(ConsentVaultError):
    """The run found a key past its rotation age, a census row on an old version, or a step that failed. ``report`` holds
    the whole run's answer."""

    def __init__(self, message: str, report: Optional[dict] = None) -> None:
        super().__init__(message)
        self.report = report if report is not None else {}


class LifecycleLoginRefused(ConsentVaultError):
    """The login is not a member of the operator console group: it lacks the grants a rotation needs, so it would fail
    part way through every organisation."""


def is_console_login(conn: psycopg.Connection) -> bool:
    row = conn.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = %s"
                       " AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')) AS member", (CONSOLE_GROUP,)).fetchone()
    return bool(row["member"])


def require_console_login(conn: psycopg.Connection) -> None:
    from .job_logins import privileged

    why = privileged(conn)
    if why:
        raise LifecycleLoginRefused(f"{why}: the key rotation runs only with the operator console's grants. Run this job "
                                    "as the key-lifecycle login", code='lifecycle_login_privileged')
    if is_console_login(conn):
        return
    who = conn.execute("SELECT current_user AS u").fetchone()["u"]
    raise LifecycleLoginRefused(f"login {who} is not a member of {CONSOLE_GROUP}: the key rotation needs the operator "
                                "console's grants. Run this job as the key-lifecycle login", code='lifecycle_login_not_in_console')


def _check_days(days: Any) -> int:
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_ROTATION_DAYS:
        raise KeyLifecycleError(f"the rotation age must be a whole number of days from 1 to {MAX_ROTATION_DAYS}; got "
                                f"{days!r}; nothing was run")
    return days


def rotation_days_from(env: Mapping[str, str]) -> int:
    """The rotation age in days from ``CONSENTVAULT_KEY_ROTATION_DAYS`` (default 365)."""
    raw = env.get(ENV_ROTATION_DAYS)
    if raw is None or raw == "":
        return DEFAULT_ROTATION_DAYS
    if not raw.strip().isdigit():
        raise KeyLifecycleError(f"{ENV_ROTATION_DAYS} must be a whole number of days; got {raw!r}; nothing was run")
    return _check_days(int(raw.strip()))


def _org_ids(connect: Callable[[], psycopg.Connection]) -> list[uuid.UUID]:
    with connect() as conn:
        return [r["o"] for r in conn.execute("SELECT o FROM consentvault.restore_org_ids() AS o")]


def _read_org(conn: psycopg.Connection, token_key, org: uuid.UUID) -> dict:
    """Inside the organisation: its status, its key versions with their ages, an open rotation, and the census of every
    version that is neither active nor destroyed."""
    from .tenancy.erasure import operator_org

    with operator_org(conn, token_key, org):
        status = conn.execute("SELECT status FROM consentvault.organization WHERE org_id ="
                              " (SELECT consentvault.current_org())").fetchone()
        keys = conn.execute("SELECT version, status, extract(epoch FROM clock_timestamp() - created_at)::float8 AS age"
                            " FROM consentvault.org_key WHERE org_id = (SELECT consentvault.current_org()) ORDER BY version"
                            ).fetchall()
        open_rot = conn.execute("SELECT 1 FROM consentvault.key_rotation WHERE org_id = (SELECT consentvault.current_org())"
                                " AND status NOT IN ('complete', 'cancelled') LIMIT 1").fetchone() is not None
        old = {}
        for k in keys:
            if k["status"] in ("active", "destroyed"):
                continue
            kinds = {r["kind"]: int(r["n"]) for r in conn.execute(
                "SELECT kind, n FROM consentvault.key_version_census(%s)", (k["version"],))}
            old[k["version"]] = {"status": k["status"], "kinds": {kind: n for kind, n in kinds.items() if n > 0}}
    if status is None:
        raise KeyLifecycleError(f"organisation {org} has no organisation row under its own token")
    active = [k for k in keys if k["status"] == "active"]
    return {"status": status["status"], "active": active[-1] if active else None, "open_rotation": open_rot, "old": old}


def _reason(exc: BaseException) -> str:
    """The error's class, and its SQLSTATE or contract name; never its text (a database error's detail can quote a row,
    an email address among them)."""
    if isinstance(exc, psycopg.Error):
        return f"{type(exc).__name__} (SQLSTATE {exc.sqlstate})"
    cause = exc.__cause__
    if isinstance(cause, psycopg.Error):
        return f"{type(exc).__name__} from {type(cause).__name__} (SQLSTATE {cause.sqlstate})"
    name = getattr(exc, "name", None)  # an ApiError's contract name (key_unavailable, rotation_in_progress, ...)
    return f"{type(exc).__name__}{f' {name}' if isinstance(name, str) else ''}"


def counts(report: dict) -> dict[str, int]:
    """The two alarm metrics of a run: keys past their rotation age, and versions with anything still wrapped under them."""
    return {"KeysPastRotationAge": len(report.get("past_rotation_age", [])),
            "KeysOnOldVersion": len(report.get("on_old_version", []))}


def run(connect: Callable[[], psycopg.Connection], *, token_key, custody, crypto, ledger, request_id: str,
        rotation_days: int = DEFAULT_ROTATION_DAYS, backup_retention_days: Optional[int] = None,
        operator_id: str = OPERATOR_ID) -> dict:
    """One run of the job (see the module text). Returns the report on a clean run, raises ``KeyLifecycleError`` with it
    otherwise, and ``LifecycleLoginRefused`` before touching anything when the login is not a console login."""
    from .tenancy import key_rotation as kr

    days = _check_days(rotation_days)
    with connect() as conn:
        require_console_login(conn)
    limit = days * DAY_SECONDS
    report: dict[str, Any] = {"rotation_days": days, "started": [], "skipped": [], "failures": [],
                              "past_rotation_age": [], "on_old_version": [], "orgs": 0}

    orgs = _org_ids(connect)
    report["orgs"] = len(orgs)
    for org in orgs:  # 1. start every rotation that is due
        try:
            with connect() as conn:
                state = _read_org(conn, token_key, org)
                if state["status"] in SKIPPED_STATUSES:
                    report["skipped"].append(str(org))
                    continue
                key = state["active"]
                if key is None or state["open_rotation"] or key["age"] < limit:
                    continue
                age_days = int(key["age"] // DAY_SECONDS)
                kr.start_rotation(conn, token_key=token_key, custody=custody, operator_id=operator_id,
                                  request_id=request_id, org_id=org,
                                  reason=f"scheduled: version {key['version']} is {age_days} days old, the rotation age "
                                         f"is {days} days")
                report["started"].append(str(org))
        except _STEP_ERRORS as exc:  # loud-failure-exempt: named in failures; the run raises once every organisation was tried
            report["failures"].append({"org_id": str(org), "step": "start", "reason": _reason(exc)})

    try:  # 2. every open rotation to the end, then the retained versions whose time has come
        kr.run_rotation_job(connect, token_key=token_key, custody=custody, crypto=crypto, ledger=ledger,
                            request_id=request_id, operator_id=operator_id, backup_retention_days=backup_retention_days)
    except kr.KeyRotationError as exc:  # loud-failure-exempt: each organisation is named below; the run raises at the end
        named = [o for o in orgs if str(o) in exc.org_ids]  # the error's own field, never its text
        for org in named or [None]:
            report["failures"].append({"org_id": str(org) if org else None, "step": "rotate", "reason": _reason(exc)})

    skipped = set(report["skipped"])
    for org in orgs:  # 3. the census, read again after the run
        if str(org) in skipped:
            continue
        try:
            with connect() as conn:
                state = _read_org(conn, token_key, org)
        except _STEP_ERRORS as exc:  # loud-failure-exempt: named in failures; the run raises once every organisation was tried
            report["failures"].append({"org_id": str(org), "step": "census", "reason": _reason(exc)})
            continue
        if state["status"] in SKIPPED_STATUSES:
            continue
        key = state["active"]
        if key is not None and key["age"] >= limit:
            report["past_rotation_age"].append({"org_id": str(org), "version": key["version"],
                                                "age_days": int(key["age"] // DAY_SECONDS)})
        for version, old in sorted(state["old"].items()):
            if old["kinds"]:
                report["on_old_version"].append({"org_id": str(org), "version": version, "status": old["status"],
                                                 "kinds": old["kinds"]})

    if report["failures"] or report["past_rotation_age"] or report["on_old_version"]:
        parts = [f"{len(report['past_rotation_age'])} key(s) past the rotation age of {days} days: "
                 + ", ".join(f"organisation {r['org_id']} version {r['version']} ({r['age_days']} days)"
                             for r in report["past_rotation_age"]),
                 f"{len(report['on_old_version'])} old version(s) still wrapping keys: "
                 + ", ".join(f"organisation {r['org_id']} version {r['version']} {r['kinds']}"
                             for r in report["on_old_version"]),
                 f"{len(report['failures'])} step(s) failed: "
                 + "; ".join(f"organisation {f['org_id']} {f['step']}: {f['reason']}" for f in report["failures"])]
        raise KeyLifecycleError("the key lifecycle run found problems. " + ". ".join(parts), report)
    return report
