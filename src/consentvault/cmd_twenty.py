"""``consentvault twenty-reconcile``: the Twenty connector's reconcile and nightly scan (twenty.md 3.5), one pass over every
organisation, under the job's own login.

Settings: the worker's (``cmd_sync``: dsn, operator_dsn, key provider, tenant token key, egress URL and secret) and
``CONSENTVAULT_CAPTURE_DB_USER`` (default ``consentvault_runtime``). The job's own login (``consentvault_twenty_login`` in the
cloud) is a member of ``consentvault_worker``: it writes Twenty's fields under a worker token, as the sync worker does. A stop it
finds is recorded through the ordinary signal path under a ``capture`` token, exactly as the webhook receiver does, on a second
connection: the same database address as the runtime group's login. Either login in the wrong group exits 3 naming it, before
anything runs. A pass in which any system's reconcile failed exits 2, so the job runner sends no heartbeat and the missed-heartbeat
alarm fires; a clean pass exits 0. Two EMF metrics are written every pass, zeros included: TwentyReconcileFailures and
TwentyHiddenStops (each hidden stop is also an alarm row).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .cli import EXIT_BROKEN, EXIT_ERROR, EXIT_OK, register
from .errors import ConfigError

ENV_CAPTURE_USER = "CONSENTVAULT_CAPTURE_DB_USER"
DEFAULT_CAPTURE_USER = "consentvault_runtime"


class WrongLoginError(ConfigError):
    """The job's database login is not its own (a member of both the worker and the runtime group)."""


def _member(conn, group: str) -> tuple[str, bool]:
    row = conn.execute("SELECT current_user AS u, pg_catalog.pg_has_role(current_user, %s, 'MEMBER') AS ok", (group,)).fetchone()
    return row["u"], bool(row["ok"])


def login_problem(conn, capture) -> str | None:
    who, ok = _member(conn, "consentvault_worker")
    if not ok:
        return f"login {who} is not a member of consentvault_worker; the Twenty reconcile runs only as its own login"
    who, ok = _member(capture, "consentvault_app")
    if not ok:
        return f"capture login {who} is not a member of consentvault_app; a stop could not be recorded"
    return None


def require_job_logins(conn, capture) -> None:
    problem = login_problem(conn, capture)
    if problem:
        raise WrongLoginError(problem)


def with_user(dsn: str, user: str) -> str:
    """The job's DSN with its login swapped for ``user`` (the same host and database; an IAM DSN signs for that user)."""
    import re

    if not re.match(r"^[a-z][a-z0-9+.-]*://[^@/]+@", dsn):
        raise WrongLoginError("the job's DSN names no login, so the capture login cannot be derived from it")
    return re.sub(r"^([a-z][a-z0-9+.-]*://)[^@/]+@", lambda m: m.group(1) + user + "@", dsn, count=1)


def run_pass(conn, connect, reconciler, token_key) -> dict:
    """One pass: each live Twenty system that is due is reconciled. ``conn`` holds the worker tokens; ``connect`` opens a
    second connection under the same login for the capture side. A system that fails is named in ``failed``; the others run."""
    from .sync.connectors.twenty_reconcile import due
    from .tenancy.tokens import mint_org_token, org_transaction

    out = {"systems": 0, "failed": [], "hidden_stops": 0, "stops_found": 0}
    for org_id in [r["o"] for r in conn.execute("SELECT o FROM consentvault.dispatch_org_ids('sync') AS o")]:
        token = conn.execute("SELECT consentvault.dispatch_org_token('sync', %s) AS t", (org_id,)).fetchone()["t"]
        with org_transaction(conn, token):
            systems = conn.execute("SELECT * FROM consentvault.connector_systems() WHERE status = 'active'").fetchall()
        for s in systems:
            run, full = due(s)   # decided by the database's clock
            if not run:
                continue
            out["systems"] += 1
            capture = mint_org_token(token_key, org_id, ("capture",), credential_id=None, ttl_seconds=300)
            try:
                with connect() as app:
                    rep = reconciler.run(app, capture, conn, token, org_id, s["system_id"], full=full)
            except Exception as exc:  # loud-failure-exempt: named in 'failed', counted in TwentyReconcileFailures, exit 2, no heartbeat
                # the allowlist logging rule: the error type and the ids, never a message (it can carry a contact or an address)
                out["failed"].append({"org_id": str(org_id), "system_id": str(s["system_id"]), "error": type(exc).__name__})
                continue
            out["hidden_stops"] += rep.stops_hidden
            out["stops_found"] += rep.stops_found
    return out


def _run(args, cfg) -> int:
    from . import metrics
    from .cmd_sync import _token_key, build_worker
    from .sync.connectors.twenty_reconcile import TwentyReconcile

    from . import db

    worker, connect = build_worker(cfg, os.environ)
    if not hasattr(worker.transport, "call"):
        raise ConfigError("the egress transport has no /call; the Twenty reconcile cannot reach Twenty")
    capture_dsn = with_user(cfg.require_dsn(), os.environ.get(ENV_CAPTURE_USER) or DEFAULT_CAPTURE_USER)
    with connect() as conn, db.connect(capture_dsn) as capture:
        problem = login_problem(conn, capture)
    if problem:
        print(json.dumps({"twenty_reconcile": "refused", "error": problem}), flush=True)
        return EXIT_BROKEN
    with connect() as conn:
        reconciler = TwentyReconcile(worker.crypto, worker.custody, worker.transport, clock=lambda: datetime.now(timezone.utc))
        out = run_pass(conn, lambda: db.connect(capture_dsn), reconciler, _token_key(os.environ))
    metrics.emit("TwentyReconcileFailures", len(out["failed"]))
    metrics.emit("TwentyHiddenStops", out["hidden_stops"])
    print(json.dumps({"twenty_reconcile": "done" if not out["failed"] else "failed", **out}), flush=True)
    return EXIT_OK if not out["failed"] else EXIT_ERROR


def _args(p) -> None:
    return None


register("twenty-reconcile", "reconcile every due Twenty system once (stops missed by a webhook, hidden stops)", _run, _args)


# ---- twenty-workflow-reminders ---------------------------------------------------------------------------------------------
ENV_NOTIFIER = "CONSENTVAULT_NOTIFIER"
ENV_PORTAL_URL = "CONSENTVAULT_PORTAL_URL"


class NoAdminAddress(ConfigError):
    """A workflow credential reminder is due and the organisation has no admin with an email address on record."""


def _reminder_event(row) -> str:
    return (f"the gate credential your Twenty workflow uses stops working in {row['days_left']} days"
            f" ({row['ends_at']:%Y-%m-%d}); create its replacement on the system screen and paste it into the workflow")


def run_reminders(conn, notifier, portal_url: str) -> dict:
    """One pass of the workflow credential reminders (twenty.md 4.2): in each organisation, the 14-day and 3-day reminders due
    now are emailed to its admins as a ``security_alert``. Each organisation is one transaction: a send that fails, or an
    organisation with no admin address, rolls its reminders back so they stay due, and is named in ``failed``."""
    from .notify.errors import NotifyRefused, SendFailed
    from .sync.connectors import twenty_workflow as wf
    from .tenancy.tokens import org_transaction

    now = datetime.now(timezone.utc)   # the email's own timestamp only; the database's clock decides what is due
    out = {"sent": 0, "failed": []}
    for org_id in [r["o"] for r in conn.execute("SELECT o FROM consentvault.dispatch_org_ids('sync') AS o")]:
        token = conn.execute("SELECT consentvault.dispatch_org_token('sync', %s) AS t", (org_id,)).fetchone()["t"]
        sent = 0
        try:
            with org_transaction(conn, token):
                for row in wf.reminders_due(conn):
                    if not row["admin_emails"]:
                        raise NoAdminAddress("no admin of the organisation has an email address on record")
                    for to in row["admin_emails"]:
                        notifier.send("security_alert", to, {"company": row["company"], "event": _reminder_event(row),
                                                             "when": now.strftime("%Y-%m-%d %H:%M UTC"),
                                                             "review_url": f"{portal_url.rstrip('/')}/systems/{row['system_id']}"})
                    sent += 1
        except (NoAdminAddress, SendFailed, NotifyRefused) as exc:  # loud-failure-exempt: named in 'failed', exit 2, no heartbeat; the reminders stay due
            out["failed"].append({"org_id": str(org_id), "error": type(exc).__name__})
            continue
        out["sent"] += sent
    return out


def _run_reminders(args, cfg) -> int:
    from . import db
    from .providers.plugins import resolve_object

    portal = (os.environ.get(ENV_PORTAL_URL) or "").strip()
    if not portal.startswith("https://"):
        raise ConfigError(f"{ENV_PORTAL_URL} must be the portal's https address; the reminders link to the system screen")
    name = (os.environ.get(ENV_NOTIFIER) or "").strip()
    if not name:
        raise ConfigError(f"{ENV_NOTIFIER} is not set; the workflow credential reminders cannot be emailed")
    notifier = resolve_object(name).from_environment(os.environ)
    with db.connect(cfg.require_dsn()) as conn:
        who, ok = _member(conn, "consentvault_worker")
        if not ok:
            print(json.dumps({"twenty_workflow_reminders": "refused",
                              "error": f"login {who} is not a member of consentvault_worker"}), flush=True)
            return EXIT_BROKEN
        out = run_reminders(conn, notifier, portal)
    print(json.dumps({"twenty_workflow_reminders": "done" if not out["failed"] else "failed", **out}), flush=True)
    return EXIT_OK if not out["failed"] else EXIT_ERROR


register("twenty-workflow-reminders", "email the 14-day and 3-day Twenty workflow credential reminders that are due",
         _run_reminders, _args)
