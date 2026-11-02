"""``consentvault restore-drill``: the restore drill (``restore_drill``), on its schedule.

Settings, both deployments: the drill's own production login (``CONSENTVAULT_DSN``, or the IAM login ``CV_DB_USER``: a
member of ``consentvault_restore_drill``), the tenant token key (``CONSENTVAULT_TOKEN_KEY_ID``,
``CONSENTVAULT_TOKEN_KEY_FILE``), the key provider, the lifecycle ledger's store, the evidence store, and optionally
``CONSENTVAULT_RESTORE_DRILL_TARGET_SECONDS`` (default 14400).

Self-host: ``CONSENTVAULT_RESTORE_DRILL_BACKUP_DIR`` (the pg_dump archives), ``CONSENTVAULT_RESTORE_DRILL_ADMIN_DSN`` (a
superuser on the server the scratch database is made on), ``CONSENTVAULT_OPERATOR_DSN`` (the operator console login, used
on the copy), ``CONSENTVAULT_EVIDENCE_DIR``, and optionally ``CONSENTVAULT_RESTORE_DRILL_PG_RESTORE``.
Cloud (``db_auth = iam``): the scratch instance settings ``providers.rds_restore`` reads; the evidence bucket is listed for
the objects written after the backup.

Exit 0: the drill passed and is recorded. Exit 3: the drill failed (it is recorded as failed), or the login is not the
drill login. Exit 2: a setting is missing or the drill could not start (nothing was restored).
"""

from __future__ import annotations

import json
import os
import sys
import uuid

from .safelog import describe
from .cli import EXIT_BROKEN, EXIT_OK, register
from .errors import ConfigError

ENV_BACKUP_DIR = "CONSENTVAULT_RESTORE_DRILL_BACKUP_DIR"
ENV_ADMIN_DSN = "CONSENTVAULT_RESTORE_DRILL_ADMIN_DSN"
ENV_PG_RESTORE = "CONSENTVAULT_RESTORE_DRILL_PG_RESTORE"


def _need(env, name: str) -> str:
    value = env.get(name)
    if not value:
        raise ConfigError(f"the restore drill needs {name}; nothing was restored")
    return value


def _run_job(cfg, env):
    from . import restore_drill as rd
    from .cmd_cloud import evidence_store_only
    from .cmd_erasure import _token_key, ledger_store
    from . import dbclock
    from .db import connect
    from .providers.plugins import load_key_provider
    from .tenancy.crypto import TenantCrypto
    from .tenancy.erasure import LifecycleLedger
    from .tenancy.keys_adapter import CustodyKeyAdapter
    from .tenancy.restore import local_inventory

    cloud = cfg.db_auth == "iam"
    dsn = cfg.require_dsn()
    seconds = rd.target_seconds_from(env)
    with connect(dsn) as conn:
        rd.require_drill_login(conn)
    key = _token_key()
    ledger = LifecycleLedger(ledger_store(env, cloud=cloud), clock=dbclock.datetime_clock(lambda: connect(dsn)))
    store = evidence_store_only(cfg, env)
    custody = load_key_provider(cfg.key_provider, env=env)
    if cloud:
        from .providers.rds_restore import RdsSnapshotTarget

        target = RdsSnapshotTarget.from_environment(env)
        inventory = store.inventory
    else:
        target = rd.PgDumpTarget(backup_dir=_need(env, ENV_BACKUP_DIR), admin_dsn=_need(env, ENV_ADMIN_DSN),
                                 console_dsn=cfg.require_operator_dsn(), pg_restore=env.get(ENV_PG_RESTORE) or None)
        inventory = local_inventory(_need(env, "CONSENTVAULT_EVIDENCE_DIR"))
    return rd.run_drill(target, record_connect=lambda: connect(dsn), token_key=key,
                        crypto_for=lambda scratch: TenantCrypto(CustodyKeyAdapter.from_database(custody, scratch, key)),
                        store=store, ledger=ledger, inventory=inventory, target_seconds=seconds,
                        request_id=f"job-drill-{uuid.uuid4().hex[:12]}")


def run_command(args, cfg) -> int:
    from . import restore_drill as rd

    try:
        record = _run_job(cfg, os.environ)
    except rd.DrillLoginRefused as exc:
        print(f"consentvault: {describe(exc)}", file=sys.stderr)
        return EXIT_BROKEN
    except rd.DrillFailed as exc:
        print(f"consentvault: {describe(exc)}", file=sys.stderr)
        print(json.dumps(exc.record, sort_keys=True, default=str))
        return EXIT_BROKEN
    print(json.dumps(record, sort_keys=True, default=str))
    return EXIT_OK


register("restore-drill", "restore the latest backup into a scratch database, prove it, time it and record it", run_command)
