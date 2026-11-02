"""``consentvault erasure-resume``: the scheduled erasure job.

Runs every confirmed erasure that waited for its person's stop pushes to be delivered or dead
(``pending_suppression_delivery``), queues behind a hold any that a hold now covers, and writes the lifecycle ledger
commit of every completed erasure (``tenancy.erasure.resume_waiting``). It enters each organisation on the operator
console's connection with a short tenant token, so it needs:

- ``CONSENTVAULT_OPERATOR_DSN`` (or ``operator_dsn``): the operator console's login (never the schema owner);
- ``CONSENTVAULT_TOKEN_KEY_ID`` and ``CONSENTVAULT_TOKEN_KEY_FILE``: the tenant token key, the file holding its secret as
  hex (at least 32 bytes);
- the lifecycle ledger's write-once store: ``CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET`` (cloud, S3 Object Lock) or
  ``CONSENTVAULT_LIFECYCLE_LEDGER_DIR`` (self-host); see ``ledger_store``.

A missing setting is a named error (exit 2). An erasure that still waits, or a commit the ledger could not take yet
(an alarm row is written), is in the printed answer and the next run picks it up.
"""

from __future__ import annotations

import json
import os
import uuid

import psycopg
import psycopg.errors

from . import dbclock
from .safelog import describe
from .cli import EXIT_BROKEN, EXIT_OK, register
from .errors import ConfigError

ENV_TOKEN_KEY_ID = "CONSENTVAULT_TOKEN_KEY_ID"
ENV_TOKEN_KEY_FILE = "CONSENTVAULT_TOKEN_KEY_FILE"
ENV_LEDGER_DIR = "CONSENTVAULT_LIFECYCLE_LEDGER_DIR"
ENV_LEDGER_BUCKET = "CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET"
ENV_LEDGER_REGION = "CONSENTVAULT_LIFECYCLE_LEDGER_REGION"


def _need(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"the erasure job needs {name}; nothing was run")
    return value


def ledger_store(env, *, cloud: bool = False):
    """The lifecycle ledger's write-once store. Cloud: ``CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET`` (an S3 bucket with Object
    Lock, written in COMPLIANCE mode on the task role's credentials; region ``CONSENTVAULT_LIFECYCLE_LEDGER_REGION`` or
    ``AWS_REGION``). Self-host: ``CONSENTVAULT_LIFECYCLE_LEDGER_DIR``. Exactly one is set. In cloud mode (``db_auth = "iam"``) a local folder is refused:
    a folder on the task's disk is lost with the task, and the ledger is the record a restore replays."""
    from .providers.evidence import LocalAppendOnlyEvidenceStore, S3ObjectLockEvidenceStore
    from .providers.rds_iam import ContainerCredentials

    bucket, folder = env.get(ENV_LEDGER_BUCKET), env.get(ENV_LEDGER_DIR)
    if bucket and folder:
        raise ConfigError(f"set one lifecycle ledger store, not both: {ENV_LEDGER_BUCKET} (cloud) or {ENV_LEDGER_DIR}"
                          " (self-host); nothing was run")
    if cloud and folder:
        raise ConfigError(f"{ENV_LEDGER_DIR} is a local folder and is refused in cloud mode (db_auth = iam): set "
                          f"{ENV_LEDGER_BUCKET} to the Object Lock bucket; nothing was run")
    if folder:
        return LocalAppendOnlyEvidenceStore(folder)
    if not bucket:
        raise ConfigError(f"the erasure job needs {ENV_LEDGER_BUCKET} (cloud) or {ENV_LEDGER_DIR} (self-host); "
                          "nothing was run")
    region = env.get(ENV_LEDGER_REGION) or env.get("AWS_REGION")
    if not region:
        raise ConfigError(f"the erasure job needs {ENV_LEDGER_REGION} (or AWS_REGION) for {ENV_LEDGER_BUCKET}; "
                          "nothing was run")
    return S3ObjectLockEvidenceStore(endpoint="https" + f"://s3.{region}.amazonaws.com", bucket=bucket, region=region,
                                     credentials=ContainerCredentials(env=env))


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
    from .providers.plugins import load_key_provider
    from .tenancy.crypto import TenantCrypto
    from .tenancy.erasure import LifecycleLedger, resume_waiting
    from .tenancy.keys_adapter import CustodyKeyAdapter

    key = _token_key()
    operator_dsn = cfg.require_operator_dsn()
    ledger = LifecycleLedger(ledger_store(os.environ, cloud=cfg.db_auth == "iam"),
                             clock=dbclock.datetime_clock(lambda: connect(operator_dsn)))
    custody = load_key_provider(cfg.key_provider, env=os.environ)
    crypto = TenantCrypto(CustodyKeyAdapter.from_database(custody, lambda: connect(operator_dsn), key))
    with connect(cfg.require_operator_dsn()) as conn:
        done = resume_waiting(conn, token_key=key, ledger=ledger, crypto=crypto, request_id=f"job-erasure-{uuid.uuid4().hex[:12]}")
    print(json.dumps(done, sort_keys=True, default=str))
    return EXIT_OK


register("erasure-resume", "run confirmed erasures that waited for delivery, then write their ledger commits",
         _run_erasure_resume)


def _run_erasure_commit_sweep(args, cfg) -> int:
    """The hourly commit sweep. It needs the operator console's grants (read the requests and stop events, insert the commit
    record and the alarm) and nothing else: no key provider, no KMS role, no key custody, because it never opens a
    contact key. In the cloud it runs as its own task role whose database user is a member of consentvault_console, with
    read and write on the lifecycle ledger bucket only. The worker and runtime logins hold none of those grants."""
    from .db import connect
    from .tenancy.erasure import LifecycleLedger, commit_sweep

    key = _token_key()
    ledger = LifecycleLedger(ledger_store(os.environ, cloud=cfg.db_auth == "iam"),
                             clock=dbclock.datetime_clock(lambda: connect(cfg.require_operator_dsn())))
    try:
        with connect(cfg.require_operator_dsn()) as conn:
            done = commit_sweep(conn, token_key=key, ledger=ledger, request_id=f"job-commit-{uuid.uuid4().hex[:12]}")
    except psycopg.errors.InsufficientPrivilege as exc:
        raise ConfigError("the erasure-commit-sweep login lacks a grant it needs "
                          f"({describe(exc)}): it must be a member of consentvault_console (the operator "
                          "console's grants), not the worker or runtime login") from exc
    print(json.dumps(done, sort_keys=True, default=str))
    return EXIT_OK if not done["overdue"] else EXIT_BROKEN


register("erasure-commit-sweep", "write due ledger commits; alarm and fail when an intent is over an hour old without one",
         _run_erasure_commit_sweep)
