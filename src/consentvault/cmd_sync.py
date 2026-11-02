"""``consentvault sync-worker``: run the suppression sync worker (sync/README.md section 3).

Settings (environment, or consentvault.toml where noted):

- ``dsn`` / ``CONSENTVAULT_DSN``, or ``db_auth = "iam"`` and its settings: the worker's database login;
- ``operator_dsn`` / ``CONSENTVAULT_OPERATOR_DSN`` (the IAM login when ``db_auth = "iam"``): the connection that reads
  each organisation's wrapped fingerprint secret;
- ``key_provider`` / ``CONSENTVAULT_KEY_PROVIDER``: ``openbao`` in the self-host, the managed service's plugin in the
  cloud (``consentvault.providers.plugins``);
- ``CONSENTVAULT_TOKEN_KEY_ID`` and ``CONSENTVAULT_TOKEN_KEY_FILE``: the tenant token key (hex in the file);
- ``CONSENTVAULT_EGRESS_URL`` and ``CONSENTVAULT_EGRESS_SECRET_FILE``: the egress Worker and its secret.

A missing setting is a named error (exit 2) and nothing runs. ``--once`` runs one pass and exits non-zero if it failed;
without it the worker runs until SIGTERM or SIGINT, a failed pass logged at ERROR and the next one started.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import threading
from pathlib import Path
from typing import Mapping

from .safelog import describe
from .cli import EXIT_OK, register
from .errors import ConfigError

ENV_TOKEN_KEY_ID = "CONSENTVAULT_TOKEN_KEY_ID"
ENV_TOKEN_KEY_FILE = "CONSENTVAULT_TOKEN_KEY_FILE"
ENV_EGRESS_URL = "CONSENTVAULT_EGRESS_URL"
ENV_EGRESS_SECRET_FILE = "CONSENTVAULT_EGRESS_SECRET_FILE"


def _need(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not value:
        raise ConfigError(f"the sync worker needs {name}; nothing was run")
    return value


def _read(env: Mapping[str, str], name: str) -> str:
    path = _need(env, name)
    try:
        text = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ConfigError(f"{name} cannot be read ({type(exc).__name__}); nothing was run") from exc
    if not text:
        raise ConfigError(f"{name} names an empty file; nothing was run")
    return text


def _token_key(env: Mapping[str, str]):
    from .tenancy.errors import TenantTokenError
    from .tenancy.tokens import TokenKey

    raw = _read(env, ENV_TOKEN_KEY_FILE)
    try:
        return TokenKey(_need(env, ENV_TOKEN_KEY_ID), bytes.fromhex(raw))
    except (ValueError, TenantTokenError) as exc:
        raise ConfigError(f"{ENV_TOKEN_KEY_FILE} or {ENV_TOKEN_KEY_ID} is not a usable tenant token key: {describe(exc)}") from exc


def build_worker(cfg, env: Mapping[str, str]):
    """The worker and its no-argument connect, from configuration. Raises ``ConfigError`` naming any missing setting."""
    from . import db
    from .providers.plugins import load_key_provider
    from .sync.connectors.webhook import EgressTransport
    from .sync.errors import SyncError
    from .sync.worker import SyncWorker
    from .tenancy.crypto import TenantCrypto
    from .tenancy.keys_adapter import CustodyKeyAdapter

    custody = load_key_provider(cfg.key_provider, env=env)
    token_key = _token_key(env)
    url, secret = _need(env, ENV_EGRESS_URL), _read(env, ENV_EGRESS_SECRET_FILE)
    connect = db.connect_factory(cfg)
    operator_dsn = cfg.require_operator_dsn()
    try:
        transport = EgressTransport(url, secret)
    except SyncError as exc:
        raise ConfigError(f"{ENV_EGRESS_URL}: {describe(exc)}") from exc
    crypto = TenantCrypto(CustodyKeyAdapter.from_database(custody, lambda: db.connect(operator_dsn), token_key))
    from .sync.connectors.twenty import TwentyDelivery  # native connectors call through the same door's /call
    from datetime import datetime, timezone

    twenty = TwentyDelivery(crypto, custody, transport, clock=lambda: datetime.now(timezone.utc))
    return SyncWorker(crypto, custody, transport, twenty=twenty), connect


def _open(connect):
    return connect()


def _args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--once", action="store_true", help="run one pass and exit")
    p.add_argument("--interval", type=float, default=5.0, help="seconds between passes (default 5)")


def _run(args, cfg) -> int:
    worker, connect = build_worker(cfg, os.environ)
    if args.once:
        with _open(connect) as conn:
            worker.run_once(conn, connect=connect)
        print(json.dumps({"sync_worker": "one pass done"}), flush=True)
        return EXIT_OK
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    print(json.dumps({"sync_worker": "running", "interval_seconds": args.interval}), flush=True)
    worker.run_loop(connect, stop, interval_seconds=args.interval)
    return EXIT_OK


register("sync-worker", "run the suppression sync worker (one pass with --once, else until stopped)", _run, _args)
