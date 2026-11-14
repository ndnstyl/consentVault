"""``consentvault isolation-self-test``: the nightly isolation self-test (``isolation``).

Needs only its own login (``CONSENTVAULT_DSN``, or the IAM login ``CV_DB_USER``: a member of
``consentvault_isolation_self_test``). Exit 0: a clean run (``IsolationLeaks`` written as 0), or single-company mode (one
organisation; nothing to isolate). Exit 3: the login is wrong, or a finding (the metric carries the count, the printed
answer names each table). Exit 2: a setting is missing.
"""

from __future__ import annotations

import json
import sys

from .safelog import describe
from . import metrics
from .cli import EXIT_BROKEN, EXIT_OK, register


def _run_job(cfg):
    """The run, or None in single-company mode."""
    from . import isolation
    from .db import connect

    dsn = cfg.require_dsn()
    with connect(dsn) as conn:
        if conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"] is not None:
            return None
    return isolation.run(lambda: connect(dsn))


def run_command(args, cfg) -> int:
    from . import isolation

    try:
        report = _run_job(cfg)
    except isolation.SelfTestLoginRefused as exc:
        print(f"consentvault: {describe(exc)}", file=sys.stderr)
        return EXIT_BROKEN
    except isolation.IsolationLeak as exc:
        metrics.emit("IsolationLeaks", len(exc.report.get("findings", [])))
        print(f"consentvault: {describe(exc)}", file=sys.stderr)
        print(json.dumps({"ok": False, **exc.report}, sort_keys=True, default=str))
        return EXIT_BROKEN
    if report is None:
        print("consentvault: single-company mode: one organisation, nothing to isolate; nothing was run")
        return EXIT_OK
    metrics.emit("IsolationLeaks", 0)
    print(json.dumps({"ok": True, **report}, sort_keys=True, default=str))
    return EXIT_OK


register("isolation-self-test", "prove the canary organisations cannot read each other or anyone through any table "
         "(scheduled nightly)", run_command)
