"""``consentvault key-lifecycle``: the scheduled key-lifecycle job (``key_lifecycle``), once a day.

Needs the key-lifecycle login (``CONSENTVAULT_OPERATOR_DSN``, or the IAM login ``CV_DB_USER``: a member of
``consentvault_console``), the tenant token key (``CONSENTVAULT_TOKEN_KEY_ID``, ``CONSENTVAULT_TOKEN_KEY_FILE``), the key
provider, the lifecycle ledger's store (which versions still seal a ledger entry) and optionally
``CONSENTVAULT_KEY_ROTATION_DAYS`` (default 365) and ``CONSENTVAULT_BACKUP_RETENTION_DAYS``.

Exit 0: a clean run (both metrics written as zeros), or single-company mode (one organisation key, rotated by the
operator; nothing is run). Exit 3: the login is not a console login, or the run found a key past its age, a census row on
an old version or a failed step (the metrics carry the counts). Exit 2: a setting is missing.
"""

from __future__ import annotations

import json
import os
import sys
import uuid

from . import dbclock
from .safelog import describe
from . import metrics
from .cli import EXIT_BROKEN, EXIT_ERROR, EXIT_OK, register


def _run_job(cfg, env):
    """The run with every dependency built from the settings. None in single-company mode."""
    from . import key_lifecycle as kl
    from .cmd_erasure import _token_key, ledger_store
    from .db import connect
    from .providers.plugins import load_key_provider
    from .tenancy.crypto import TenantCrypto
    from .tenancy.erasure import LifecycleLedger
    from .tenancy.keys_adapter import CustodyKeyAdapter

    dsn = cfg.require_operator_dsn()
    days = kl.rotation_days_from(env)
    with connect(dsn) as conn:
        if conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"] is not None:
            return None
        kl.require_console_login(conn)
    key = _token_key()
    ledger = LifecycleLedger(ledger_store(env, cloud=cfg.db_auth == "iam"), clock=dbclock.datetime_clock(lambda: connect(dsn)))
    custody = load_key_provider(cfg.key_provider, env=env)
    crypto = TenantCrypto(CustodyKeyAdapter.from_database(custody, lambda: connect(dsn), key))
    return kl.run(lambda: connect(dsn), token_key=key, custody=custody, crypto=crypto, ledger=ledger,
                  request_id=f"job-keys-{uuid.uuid4().hex[:12]}", rotation_days=days,
                  backup_retention_days=cfg.backup_retention_days)


def _emit(counts: dict) -> None:
    """The two alarm metrics, by name (the ops alarms read exactly these)."""
    metrics.emit("KeysPastRotationAge", counts["KeysPastRotationAge"])
    metrics.emit("KeysOnOldVersion", counts["KeysOnOldVersion"])


def run_command(args, cfg) -> int:
    from . import key_lifecycle as kl

    try:
        report = _run_job(cfg, os.environ)
    except kl.LifecycleLoginRefused as exc:
        print(f"consentvault: {describe(exc)}", file=sys.stderr)
        return EXIT_BROKEN
    except kl.KeyLifecycleError as exc:
        if not exc.report:  # a setting refused before anything ran: no counts to report
            print(f"consentvault: {describe(exc)}", file=sys.stderr)
            return EXIT_ERROR
        _emit(kl.counts(exc.report))
        print(f"consentvault: {describe(exc)}", file=sys.stderr)
        print(json.dumps({"ok": False, **exc.report}, sort_keys=True, default=str))
        return EXIT_BROKEN
    if report is None:
        print("consentvault: single-company mode: the one organisation key is rotated by the operator; nothing was run")
        return EXIT_OK
    _emit(kl.counts(report))
    print(json.dumps({"ok": True, **report}, sort_keys=True, default=str))
    return EXIT_OK


register("key-lifecycle", "rotate organisation keys past their rotation age and check the key census (scheduled daily)",
         run_command)
