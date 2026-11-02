"""The scheduled usage jobs: ``usage-daily``, ``usage-retry`` and ``usage-acknowledge`` (``consentvault <name>``, or
``python -m consentvault.jobs <name>``).

- ``usage-daily``: counts yesterday's closed UTC day for every live organisation and reports it to Stripe's meters.
  Schedule: once a day at 00:10 UTC. ``--day YYYY-MM-DD`` re-runs one named day by hand (a backfill; it does not touch the
  run heartbeat). Gate checks come from the tally the gate keeps with each decision; a day the tally does not cover
  (before it began) names "no count" loudly and the job exits 2 for it, while the consent-event count is reported.
- ``usage-retry``: sends again the days whose send Stripe refused or could not take, once they come due, and goes red when
  no daily run has finished in 26 hours (alarm ``usage_daily_run_missed``). Schedule: every 15 minutes.
- ``usage-acknowledge``: an operator clears a standing verdict (``--org``, ``--day``, ``--key``, ``--by``); each one is
  audited and a verdict is acknowledged once.

Settings: the worker's database login (``dsn`` / ``CONSENTVAULT_DSN``, the ``consentvault_worker`` role) and
``CONSENTVAULT_STRIPE_SECRET_KEY_FILE`` (the Stripe secret key in that file). A missing setting is a named error (exit 2)
and nothing runs.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import date
from typing import Mapping

from .safelog import describe
from .cli import EXIT_OK, register
import psycopg

from .billing.errors import UsageReportError
from .errors import ConfigError, DatabaseError

ENV_STRIPE_KEY_FILE = "CONSENTVAULT_STRIPE_SECRET_KEY_FILE"


def make_client(env: Mapping[str, str] | None = None):
    """The Stripe client, from the key file the environment names."""
    from .billing.errors import StripeRejectedError
    from .billing.stripe_client import HttpStripeClient

    env = os.environ if env is None else env
    path = env.get(ENV_STRIPE_KEY_FILE)
    if not path:
        raise ConfigError(f"the usage jobs need {ENV_STRIPE_KEY_FILE}; nothing was run")
    try:
        with open(path, encoding="utf-8") as fh:
            key = fh.read().strip()
    except OSError as exc:
        raise ConfigError(f"{ENV_STRIPE_KEY_FILE} cannot be read ({type(exc).__name__}); nothing was run") from exc
    try:
        return HttpStripeClient(key)
    except StripeRejectedError as exc:
        raise ConfigError(f"{ENV_STRIPE_KEY_FILE} names an empty file; nothing was run") from exc


def _summary(run) -> str:
    return json.dumps({"day": run.day.isoformat(),
                       "orgs": [{"org": str(o.org_id), "events": o.events, "gate_checks": o.gate_checks,
                                 "reported": o.reported, "skipped": o.skipped} for o in run.orgs]}, sort_keys=True)


def _run_daily(args, cfg) -> int:
    from .billing.usage import db_gate_counter, run_daily_job, run_daily_usage
    from .db import connect

    client = make_client()
    with connect(cfg.require_dsn()) as worker:
        if args.day:
            run = run_daily_usage(worker, client, date.fromisoformat(args.day), gate_counter=db_gate_counter)
        else:
            run = run_daily_job(worker, client, gate_counter=db_gate_counter)
    print(_summary(run))
    return EXIT_OK


def _run_retry(args, cfg) -> int:
    from .billing.usage import run_usage_retries
    from .db import connect

    client = make_client()
    with connect(cfg.require_dsn()) as worker:
        run = run_usage_retries(worker, client)
    print(_summary(run))
    return EXIT_OK


def _run_acknowledge(args, cfg) -> int:
    from .billing.usage import acknowledge_day
    from .db import connect

    try:
        org, day = uuid.UUID(args.org), date.fromisoformat(args.day)
    except ValueError as exc:
        raise ConfigError(f"--org must be an organisation id and --day a date YYYY-MM-DD: {describe(exc)}") from exc
    try:
        with connect(cfg.require_dsn()) as worker:
            acknowledge_day(worker, org, day, args.key, args.by)
    except (psycopg.Error, DatabaseError) as exc:
        raise UsageReportError(f"usage-acknowledge could not run ({type(exc).__name__}): {describe(exc)}") from exc
    print(json.dumps({"acknowledged": args.key, "org": str(org), "day": day.isoformat(), "by": args.by}))
    return EXIT_OK


register("usage-daily", "count yesterday's usage for every live organisation and report it to Stripe", _run_daily,
         lambda p: p.add_argument("--day", help="re-run one closed day (YYYY-MM-DD) instead of yesterday"))
register("usage-retry", "resend usage Stripe refused, and go red when the daily run has not finished in 26 hours",
         _run_retry)


def _ack_args(p) -> None:
    p.add_argument("--org", required=True, help="the organisation id")
    p.add_argument("--day", required=True, help="the usage day (YYYY-MM-DD)")
    p.add_argument("--key", required=True, help="abandoned, unconfirmed:<meter> or failed:<meter>")
    p.add_argument("--by", required=True, help="who is acknowledging it")


register("usage-acknowledge", "acknowledge a standing usage verdict (audited, once)", _run_acknowledge, _ack_args)
