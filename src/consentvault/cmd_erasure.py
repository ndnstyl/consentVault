"""``consentvault erasure-resume``: the scheduled erasure job.

Runs every confirmed erasure that waited for its person's stop pushes to be delivered or dead
(``pending_suppression_delivery``), queues behind a hold any that a hold now covers, and writes the lifecycle ledger
commit of every completed erasure (``tenancy.erasure.resume_waiting``). It enters each organisation on the operator
console's connection with a short tenant token, so it needs:

- ``CONSENTVAULT_OPERATOR_DSN`` (or ``operator_dsn``): the operator console's login (never the schema owner);
- ``CONSENTVAULT_TOKEN_KEY_ID`` and ``CONSENTVAULT_TOKEN_KEY_FILE``: the tenant token key, the file holding its secret as
  hex (at least 32 bytes);
- ``CONSENTVAULT_LIFECYCLE_LEDGER_DIR``: the write-once archive store that holds the lifecycle ledger.

A missing setting is a named error (exit 2). An erasure that still waits, or a commit the ledger could not take yet
(an alarm row is written), is in the printed answer and the next run picks it up.
"""

from __future__ import annotations

import json
import os
import uuid

from .cli import EXIT_OK, register
from .errors import ConfigError

ENV_TOKEN_KEY_ID = "CONSENTVAULT_TOKEN_KEY_ID"
ENV_TOKEN_KEY_FILE = "CONSENTVAULT_TOKEN_KEY_FILE"
ENV_LEDGER_DIR = "CONSENTVAULT_LIFECYCLE_LEDGER_DIR"


def _need(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"the erasure job needs {name}; nothing was run")
    return value


def _token_key():
    from .tenancy.tokens import TokenKey

    path = _need(ENV_TOKEN_KEY_FILE)
    try:
        with open(path, encoding="utf-8") as fh:
            secret = bytes.fromhex(fh.read().strip())
    except (OSError, ValueError) as exc:
        raise ConfigError(f"{ENV_TOKEN_KEY_FILE} could not be read as a hex secret ({type(exc).__name__}); nothing was "
                          "run") from exc
    return TokenKey(_need(ENV_TOKEN_KEY_ID), secret)


def _run_erasure_resume(args, cfg) -> int:
    from .db import connect
    from .providers.evidence import LocalAppendOnlyEvidenceStore
    from .tenancy.erasure import LifecycleLedger, resume_waiting

    key = _token_key()
    ledger = LifecycleLedger(LocalAppendOnlyEvidenceStore(_need(ENV_LEDGER_DIR)))
    with connect(cfg.require_operator_dsn()) as conn:
        done = resume_waiting(conn, token_key=key, ledger=ledger, request_id=f"job-erasure-{uuid.uuid4().hex[:12]}")
    print(json.dumps(done, sort_keys=True, default=str))
    return EXIT_OK


register("erasure-resume", "run confirmed erasures that waited for delivery, then write their ledger commits",
         _run_erasure_resume)
