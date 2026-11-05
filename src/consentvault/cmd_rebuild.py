"""``consentvault projection-rebuild``: project every stored post that has no event yet, in arrival order (the one door's rebuild).

A crash between a post's answer and its event, a database fault while the projection ran, or a post whose process had no writer
for its intake all leave a stored post with no outcome. This command finds them and projects them with the settings stored
beside each post. Run it from the scheduler (for example every 10 minutes); running it twice changes nothing.

It prints counts and the names of the posts it could not finish (the post's id and the class of the error that stopped it, never
the error's text): the posts it projected, the events it appended, the reasons it stored, and every unfinished post. Exit 2 names
how many posts it could not finish; no error is ever a final reason, so each stays unfinished, carries a recorded attempt, and is
projected again on every run. In multi-tenant mode it needs the same settings as ``serve-cloud``.
"""

from __future__ import annotations

import json
import os

from .cli import EXIT_ERROR, EXIT_OK, _connect, register


UNFINISHED_LISTED = 100


def _summary(mode: str, outcomes, failed) -> dict:
    waiting = ("awaiting_authentication", "no_writer_for_intake")
    return {"mode": mode, "projected": len(outcomes), "events": sum(1 for o in outcomes if o.event_id is not None),
            "reasons_stored": sum(1 for o in outcomes if o.event_id is None and not o.retry and o.reason not in waiting),
            "awaiting": sum(1 for o in outcomes if o.reason in waiting), "unfinished": len(failed),
            "unfinished_posts": [{"post": o.post_id, "error": o.reason} for o in failed[:UNFINISHED_LISTED]],
            "unfinished_not_listed": max(0, len(failed) - UNFINISHED_LISTED)}


def _run(args, cfg) -> int:
    from . import door

    with _connect(cfg) as conn:   # the lock is held on this connection for the whole run and goes when it closes
        if not conn.execute("SELECT pg_try_advisory_lock(hashtext('consentvault.projection-rebuild')) AS got").fetchone()["got"]:
            return _already_running()
        multi = conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"] is None
        if not multi:
            outcomes = door.rebuild(conn, backend=door.SingleBackend(cfg.default_region, cfg.purposes or None))
            failed = [o for o in outcomes if o.retry]
            print(json.dumps(_summary("single", outcomes, failed)))
            return EXIT_OK if not failed else _unfinished(len(failed))
        return _run_multi_tenant(cfg, conn)


def _run_multi_tenant(cfg, conn) -> int:
    from . import api, cmd_cloud
    from .errors import ConsentVaultError

    settings = cmd_cloud.build_cloud(cfg, os.environ)
    orgs = [r["projection_org_ids"] for r in conn.execute("SELECT * FROM consentvault.projection_org_ids()").fetchall()]
    if not orgs:
        raise ConsentVaultError("the rebuild found no organisation to project; an empty list is never an answer here")
    outcomes: list = []
    org_failures: list = []
    api.rebuild_cloud(settings, orgs, outcomes=outcomes, failures=org_failures)
    failed = [o for o in outcomes if o.retry]
    summary = _summary("multi-tenant", outcomes, failed)
    summary["organisations_failed"] = len(org_failures)
    print(json.dumps(summary))
    if org_failures:
        import sys

        print("consentvault: the rebuild failed for " + ", ".join(f"{o} ({n})" for o, n in org_failures) +
              "; every other organisation was projected", file=sys.stderr)
        return EXIT_ERROR
    if failed:
        return _unfinished(len(failed))
    return EXIT_OK


def _already_running() -> int:
    import sys

    print("consentvault: another projection-rebuild is running; two runs at once could pick different winners between copies of "
          "one request, so this one did nothing and the next scheduled run will go ahead", file=sys.stderr)
    return EXIT_ERROR


def _unfinished(n: int) -> int:
    import sys

    print(f"consentvault: {n} stored post(s) are unfinished (each is named in the summary with the class of the error that stopped "
          "it); every attempt is recorded on the post and the next run projects them again", file=sys.stderr)
    return EXIT_ERROR


register("projection-rebuild", "project every stored post that has no event, in arrival order (scheduled job)", _run)
