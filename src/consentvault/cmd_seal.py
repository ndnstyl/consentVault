"""``consentvault seal`` and ``consentvault verify-seals``."""

from __future__ import annotations

import json
import sys
from datetime import timedelta

from .safelog import describe
from . import integrity, metrics
from .cli import EXIT_BROKEN, EXIT_OK, _connect, register


def _seal_args(p) -> None:
    p.add_argument("--limit", type=int, default=100, help="most events to seal in this run")


def _run_seal(args, cfg) -> int:
    from .seal import seal_pending

    url = cfg.require_tsa_url()
    with _connect(cfg) as conn:
        try:
            per_org = integrity.per_org_mode(conn)
        except integrity.MultiTenantRefused as exc:
            print(f"consentvault: {describe(exc)}", file=sys.stderr)
            return EXIT_BROKEN
        if per_org:  # multi-tenant: every organisation, each under its own token
            ages: dict = {}
            try:
                done_orgs = integrity.seal_every_org(conn, url, args.limit, oldest_unsealed=ages)
            except integrity.IntegrityRunError as exc:
                metrics.emit("UnsealedOldestAgeSeconds", max(ages.values(), default=0.0))
                print(f"consentvault: {describe(exc)}", file=sys.stderr)
                print(json.dumps({"ok": False, "failed_orgs": [o for o, _ in exc.failures],
                                  "sealed": {o: len(v) for o, v in exc.results.items()}}))
                return EXIT_BROKEN
            metrics.emit("UnsealedOldestAgeSeconds", max(ages.values(), default=0.0))
            print(json.dumps({"ok": True, "sealed": {o: len(v) for o, v in done_orgs.items()}}))
            return EXIT_OK
        done = seal_pending(conn, url, args.limit)
        left = conn.execute("SELECT count(*) AS n FROM consentvault.unsealed_events").fetchone()["n"]
        metrics.emit("UnsealedOldestAgeSeconds", conn.execute(
            "SELECT coalesce(extract(epoch FROM now() - min(received_at)), 0)::float8 AS age"
            " FROM consentvault.unsealed_events").fetchone()["age"])
    print(json.dumps({"sealed": len(done), "event_ids": done, "unsealed_remaining": left}))
    return EXIT_OK


def _run_verify_seals(args, cfg) -> int:
    from .seal import verify_all

    with _connect(cfg) as conn:
        try:
            per_org = integrity.per_org_mode(conn)
        except integrity.MultiTenantRefused as exc:
            print(f"consentvault: {describe(exc)}", file=sys.stderr)
            return EXIT_BROKEN
        if per_org:  # multi-tenant: every organisation, each under its own token
            try:
                checked_orgs = integrity.verify_seals_every_org(conn, timedelta(seconds=cfg.seal_max_delay_seconds),
                                                           timedelta(seconds=cfg.unsealed_grace_seconds))
            except integrity.IntegrityRunError as exc:
                metrics.emit("VerifySealsFailures", len(exc.failures))
                print(f"consentvault: {describe(exc)}", file=sys.stderr)
                print(json.dumps({"ok": False, "failed_orgs": [o for o, _ in exc.failures], "checked": exc.results}))
                return EXIT_BROKEN
            metrics.emit("VerifySealsFailures", 0)
            print(json.dumps({"ok": True, "checked": checked_orgs}))
            return EXIT_OK
        checked, failures = verify_all(conn, timedelta(seconds=cfg.seal_max_delay_seconds),
                                   timedelta(seconds=cfg.unsealed_grace_seconds))
    metrics.emit("VerifySealsFailures", 1 if failures else 0)
    for f in failures:
        print(f"consentvault: seal failed for event {f.event_id}: {f.reason}", file=sys.stderr)
    print(json.dumps({"ok": not failures, "checked": checked,
                      "failed": [{"event_id": f.event_id, "reason": f.reason} for f in failures]}))
    return EXIT_OK if not failures else EXIT_BROKEN


register("seal", "timestamp unsealed events with the configured authority", _run_seal, _seal_args)
register("verify-seals", "re-verify every stored seal against its event", _run_verify_seals)
