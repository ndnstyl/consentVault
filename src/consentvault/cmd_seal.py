"""``consentvault seal`` and ``consentvault verify-seals``."""

from __future__ import annotations

import json
import sys
from datetime import timedelta

from .cli import EXIT_BROKEN, EXIT_OK, _connect, register


def _seal_args(p) -> None:
    p.add_argument("--limit", type=int, default=100, help="most events to seal in this run")


def _run_seal(args, cfg) -> int:
    from .seal import seal_pending

    url = cfg.require_tsa_url()
    with _connect(cfg) as conn:
        done = seal_pending(conn, url, args.limit)
        left = conn.execute("SELECT count(*) AS n FROM consentvault.unsealed_events").fetchone()["n"]
    print(json.dumps({"sealed": len(done), "event_ids": done, "unsealed_remaining": left}))
    return EXIT_OK


def _run_verify_seals(args, cfg) -> int:
    from .seal import verify_all

    with _connect(cfg) as conn:
        checked, failures = verify_all(conn, timedelta(seconds=cfg.seal_max_delay_seconds),
                                   timedelta(seconds=cfg.unsealed_grace_seconds))
    for f in failures:
        print(f"consentvault: seal failed for event {f.event_id}: {f.reason}", file=sys.stderr)
    print(json.dumps({"ok": not failures, "checked": checked,
                      "failed": [{"event_id": f.event_id, "reason": f.reason} for f in failures]}))
    return EXIT_OK if not failures else EXIT_BROKEN


register("seal", "timestamp unsealed events with the configured authority", _run_seal, _seal_args)
register("verify-seals", "re-verify every stored seal against its event", _run_verify_seals)
