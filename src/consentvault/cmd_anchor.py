"""``consentvault anchor``: write the current chain head to chain_head and to the configured external sink."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import psycopg

import sys

from .safelog import describe
from . import integrity
from .cli import EXIT_BROKEN, EXIT_OK, _connect, register
from .errors import AnchorError, ConsentVaultError


def _run_anchor(args, cfg) -> int:
    from .anchor import anchor, cloud_sink

    sink = args.sink or cloud_sink(cfg)
    with _connect(cfg) as conn:
        try:
            per_org = integrity.per_org_mode(conn)
        except integrity.MultiTenantRefused as exc:
            print(f"consentvault: {describe(exc)}", file=sys.stderr)
            return EXIT_BROKEN
        if per_org:  # multi-tenant: every organisation, each under its own token
            try:
                out = integrity.anchor_every_org(conn, sink)
            except integrity.IntegrityRunError as exc:
                print(f"consentvault: {describe(exc)}", file=sys.stderr)
                print(json.dumps({"ok": False, "failed_orgs": [o for o, _ in exc.failures], **exc.results},
                                 sort_keys=True))
                return EXIT_BROKEN
            print(json.dumps({"ok": True, **out}, sort_keys=True))
            return EXIT_OK
        record = anchor(conn, sink)
    print(json.dumps(record, sort_keys=True))
    return EXIT_OK


def _anchor_args(p) -> None:
    p.add_argument("--sink", help="override the configured sink: a file path or an http(s) webhook URL")


register("anchor", "write the current chain head to chain_head and the external sink", _run_anchor, _anchor_args)


TENANT_ANCHOR_JOB = "anchor"


class TenantAnchorRunError(AnchorError):
    """One or more organizations could not be anchored. ``failures`` is [(org_id, reason)]; ``results`` holds the rest."""

    def __init__(self, failures: list[tuple[str, str]], results: list[dict]) -> None:
        self.failures, self.results = failures, results
        super().__init__("could not anchor %d organization(s): %s"
                         % (len(failures), "; ".join(f"{o}: {r}" for o, r in failures)))


def anchor_payload(org_id, seq: int, row_hash: str, anchored_at: str) -> bytes:
    """The bytes the evidence key signs for one anchor record (the verifier recomputes exactly this)."""
    from .ledger import canonical_dumps

    return canonical_dumps({"org_id": str(org_id), "seq": seq, "row_hash": row_hash,
                            "anchored_at": anchored_at}).encode("utf-8")


def anchor_tenants(worker_conn: psycopg.Connection, app_conn: psycopg.Connection, signer, sink_for, *,
                   now: datetime | None = None) -> list[dict]:
    """The hourly job: sign each organization's chain head and push it to that organization's own anchor sink.

    ``worker_conn`` is a worker-role connection: it only lists the active organizations and takes one short token for
    each (``dispatch_orgs``). ``app_conn`` is a runtime-role connection that enters one organization at a time with that
    token, reads that organization's head, and records it in chain_head after the sink accepted it. ``sink_for(org_id)``
    returns the organization's ``AnchorSink``. One organization's failure never stops the others; every failure is
    named in the ``TenantAnchorRunError`` raised at the end. Returns one result per organization that was anchored.
    """
    from .evidence import _sign
    from .providers.errors import ProviderError
    from .tenancy.errors import TenancyError
    from .tenancy.tokens import org_transaction

    dispatched = worker_conn.execute(
        "SELECT org_id, token FROM consentvault.dispatch_orgs(%s)", (TENANT_ANCHOR_JOB,)).fetchall()
    results: list[dict] = []
    failures: list[tuple[str, str]] = []
    for row in dispatched:
        org = row["org_id"]
        try:
            with org_transaction(app_conn, row["token"]):
                head = app_conn.execute("SELECT seq, row_hash FROM consentvault.ledger_head()").fetchone()
                if head is None:  # nothing to anchor yet (a new organization, or the home organization of a cloud vault)
                    results.append({"org_id": str(org), "status": "empty"})
                    continue
                sink = sink_for(org)
                if sink is None:
                    raise AnchorError("no anchor sink is configured for this organization", code="no_anchor_sink")
                when = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
                stamp = when.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                record = {"seq": head["seq"], "row_hash": head["row_hash"], "anchored_at": stamp,
                          "key_id": signer.key_id, "key_version": signer.key_version,
                          "algorithm": "ECDSA_P256_SHA256",
                          "signature": _sign(signer, anchor_payload(org, head["seq"], head["row_hash"], stamp))}
                receipt = sink.publish(str(org), record)
                last = app_conn.execute(
                    "SELECT seq, row_hash FROM consentvault.chain_head"
                    " WHERE org_id = (SELECT consentvault.current_org()) ORDER BY anchored_at DESC, seq DESC LIMIT 1"
                ).fetchone()
                if last is None or (last["seq"], last["row_hash"]) != (head["seq"], head["row_hash"]):
                    app_conn.execute("INSERT INTO consentvault.chain_head (seq, row_hash, sink, anchored_at)"
                                     " VALUES (%s, %s, %s, %s)", (head["seq"], head["row_hash"], sink.label, when))
            results.append({"org_id": str(org), "status": "published", "seq": head["seq"],
                            "row_hash": head["row_hash"], "sink": receipt.sink, "tenant_owned": receipt.tenant_owned})
        except (ConsentVaultError, ProviderError, TenancyError, psycopg.Error) as exc:
            failures.append((str(org), f"{describe(exc)}"))
    if failures:
        raise TenantAnchorRunError(failures, results)
    return results
