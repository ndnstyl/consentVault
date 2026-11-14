"""The confirmation service's periodic passes (confirmations.md section 13), one command each, each one pass:

    confirmations-send        ``run_sender``: due confirmations and their retries (every minute; the first retry is due a
                              minute after the first attempt)
    confirmations-alarms      ``run_alarm_checks``: the alarms decided by time passing, and sends stuck in ``sending``
                              (every 5 minutes)
    confirmations-link-hosts  ``recheck_link_hosts``: each organisation's wording link host looked up again (hourly)
    confirmations-purge       ``purge``: unmatched texts, the test reply and a disconnected account's auth token after 30 days
                              (daily)

Settings: the two confirmation settings (``confirm.wiring``; a job refuses without them), the database (the runtime login:
the service mints its own short tenant token per organisation and runs under row security), the tenant token key
(``CONSENTVAULT_TOKEN_KEY_ID`` and ``CONSENTVAULT_TOKEN_KEY_FILE``), the key provider, and the egress Worker
(``CONSENTVAULT_EGRESS_URL`` and ``CONSENTVAULT_EGRESS_SECRET_FILE``: the link host's DNS and page probe go through it). A pass that fails exits 2 naming
only the error's class, so the job runner sends no heartbeat and the missed-heartbeat alarm fires.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Mapping

from .cli import EXIT_ERROR, EXIT_OK, register
from .errors import ConfigError

PASSES = {"confirmations-send": ("run_sender", "send the confirmation messages that are due, once"),
          "confirmations-alarms": ("run_alarm_checks", "open or clear the confirmation alarms decided by time, once"),
          "confirmations-link-hosts": ("recheck_link_hosts", "look every wording link host up again, once"),
          "confirmations-purge": ("purge", "remove confirmation data past its keep period, once")}


def build_job_service(cfg, env: Mapping[str, str]):
    """The service a job runs, from the job's own settings, or a ``ConfigError`` naming the first one missing."""
    from . import db, dbclock
    from .cmd_sync import _token_key
    from .confirm import wiring
    from .providers.plugins import load_key_provider

    if wiring.confirmation_settings(env) is None:
        raise ConfigError(f"the confirmation jobs need {wiring.ENV_API_BASE} and {wiring.ENV_EDGE_CNAME}; nothing was run")
    custody = load_key_provider(cfg.key_provider, env=env)
    token_key = _token_key(env)
    from .cmd_sync import ENV_EGRESS_SECRET_FILE, ENV_EGRESS_URL, _need, _read
    from .sync.connectors.webhook import EgressTransport

    egress = EgressTransport(_need(env, ENV_EGRESS_URL), _read(env, ENV_EGRESS_SECRET_FILE))
    connect = db.connect_factory(cfg)
    return wiring.build_service(env, connect=connect, token_key=token_key, custody=custody, clock=dbclock.epoch_clock(connect),
                                egress=egress)


def _runner(command: str):
    method = PASSES[command][0]

    def run(args, cfg) -> int:
        service = build_job_service(cfg, os.environ)
        try:
            out = getattr(service, method)()
        except Exception as exc:  # loud-failure-exempt: exit 2 names the class (never its text, which may carry a number), no heartbeat, the alarm fires
            print(f"consentvault {command}: the pass failed ({type(exc).__name__}); nothing after the failure ran", file=sys.stderr)
            return EXIT_ERROR
        print(json.dumps({"job": command, "result": out if isinstance(out, int) else None}), flush=True)
        return EXIT_OK

    return run


for _command, (_method, _help) in PASSES.items():
    register(_command, _help, _runner(_command))
