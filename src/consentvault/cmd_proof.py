"""Subcommands: proof, export, serve."""

from __future__ import annotations

import argparse
import json

from . import cli
from .config import Config

EXIT_NO_RECORD = 4


def _query_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("query", help="phone number, email address or subject key")


def _connect(cfg: Config):
    from .db import connect

    return connect(cfg.require_dsn())


def _run_proof(args, cfg) -> int:
    from .proof import canonical_dumps, lookup

    with _connect(cfg) as conn:
        result = lookup(conn, args.query, cfg.default_region)
    print(canonical_dumps(result))
    return cli.EXIT_OK if result["found"] else EXIT_NO_RECORD


def _export_args(p: argparse.ArgumentParser) -> None:
    _query_args(p)
    p.add_argument("--out", required=True, help="directory to write the bundle into")
    p.add_argument("--untrusted", help="intermediate TSA certificates to bundle (never a trust root)")


def _run_export(args, cfg) -> int:
    from .evidence import export

    with _connect(cfg) as conn:
        summary = export(conn, args.query, args.out, cfg.default_region, args.untrusted)
    print(json.dumps(summary, sort_keys=True))
    return cli.EXIT_OK if summary["found"] else EXIT_NO_RECORD


def _serve_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)


def _run_serve(args, cfg) -> int:
    from .api import load_api_settings, serve

    settings = load_api_settings(getattr(args, "config", None))
    print(json.dumps({"serving": f"{args.host}:{args.port}", "allowed_hosts": list(settings.allowed_hosts)}), flush=True)
    try:
        serve(settings, args.host, args.port)
    except KeyboardInterrupt:
        return cli.EXIT_OK
    return cli.EXIT_OK


cli.register("proof", "show the full consent timeline for a phone, email or subject key", _run_proof, _query_args)
cli.register("export", "write a self-verifying evidence bundle", _run_export, _export_args)
cli.register("serve", "run the optional HTTP API", _run_serve, _serve_args)
