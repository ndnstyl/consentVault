"""Subcommand: serve-cloud, the multi-tenant API with the portal's sign-in.

Startup checks come in a fixed order and each names what is missing; nothing is bound to a port until all pass. The portal
edge's assertion keys come FIRST: without them the portal cannot know how anyone signed in, so the service refuses to start
(``tenancy.session.require_edge_keys``, then ``cloud_startup.build_admin_app`` builds the portal app from the same keys).

Settings (environment wins over consentvault.toml where the config reader supports it):
- ``CONSENTVAULT_EDGE_ASSERTION_KEYS`` (JSON {key id: public key PEM}) or ``[edge_assertion_keys]``
- ``key_provider`` / ``CONSENTVAULT_KEY_PROVIDER`` (organization key custody), ``CONSENTVAULT_TOKEN_KEY_ID`` + ``_FILE``
- ``CONSENTVAULT_OIDC_ISSUER``, ``_AUDIENCE``, ``_JWKS_URL``; ``CONSENTVAULT_OIDC_AUDIENCE_CLAIM`` = ``client_id`` for WorkOS
- ``CONSENTVAULT_ACCESS_KEY_FILE`` / ``CONSENTVAULT_RECEIPT_KEY_FILE`` (hex Ed25519 seeds), ``CONSENTVAULT_TOKEN_ENDPOINT_URL``,
  ``CONSENTVAULT_CURSOR_KEY_FILE`` (hex, 32+ bytes); the stores (``cloud_stores``): in the cloud
  ``CONSENTVAULT_EVIDENCE_BUCKET``, ``CONSENTVAULT_ARCHIVE_BUCKET``, ``CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET`` (S3 Object Lock;
  a local folder is refused), in the self-host ``CONSENTVAULT_EVIDENCE_DIR`` and ``CONSENTVAULT_ARCHIVE_DIR``
- ``CONSENTVAULT_MAILER`` (``module:Class`` with ``from_environment``): sends invitations; in the cloud
  ``consentvault.notify.cloud:SesMailer`` (``CONSENTVAULT_MAIL_FROM``, ``CONSENTVAULT_PORTAL_URL``,
  ``CONSENTVAULT_ALERTS_TOPIC_ARN``)

- ``CONSENTVAULT_EVIDENCE_SIGNER`` / ``CONSENTVAULT_NOTIFIER`` (``module:Class`` with ``from_environment``; in the cloud
  ``consentvault_kms:KmsEvidenceSigner`` and ``consentvault.notify.cloud:SesNotifier``; a placeholder ``UNSET:...`` is
  refused by name), ``CONSENTVAULT_STRIPE_SECRET_KEY_FILE``,
  ``CONSENTVAULT_STRIPE_WEBHOOK_SECRET_FILE``, ``CONSENTVAULT_LINK_SECRET_FILE`` (hex, 32+ bytes)

- ``CONSENTVAULT_CONFIRMATIONS_API_BASE`` and ``CONSENTVAULT_CONFIRMATIONS_EDGE_CNAME``: both or neither (``confirm.wiring``).
  Both: the confirmation service behind the portal's ``/v1/confirmations/*`` routes, the provider's inbound door and the two
  public pages. Neither: those routes answer 503 by name. One alone, or a malformed value, refuses the start.

Every route family the dashboard calls is mounted (``cloud_startup.build_routes``; tests/test_cloud_routes.py compares it with the
dashboard's API client). Final-export delivery for offboarding is not wired: destruction stays operator-driven.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Mapping

from .safelog import describe
from . import cli
from .cmd_sync import ENV_EGRESS_SECRET_FILE, ENV_EGRESS_URL, _need, _read, _token_key
from .errors import ConfigError

ENV_ISSUER, ENV_AUDIENCE, ENV_JWKS = "CONSENTVAULT_OIDC_ISSUER", "CONSENTVAULT_OIDC_AUDIENCE", "CONSENTVAULT_OIDC_JWKS_URL"
ENV_AUDIENCE_CLAIM = "CONSENTVAULT_OIDC_AUDIENCE_CLAIM"


def _plugin_spec(env: Mapping[str, str], name: str) -> str:
    """A ``module:Class`` setting; a placeholder (``UNSET:<why>``, the operations repo's mark for a gap) is refused by name."""
    spec = _need(env, name)
    if spec.strip().split(":", 1)[0] == "UNSET":
        raise ConfigError(f"{name} is still a placeholder (UNSET:...); set the class that implements it. Nothing was "
                          "started")
    return spec


def _bucket_store(env: Mapping[str, str], bucket_var: str, local_var: str, what: str):
    from .providers.evidence import S3ObjectLockEvidenceStore
    from .providers.rds_iam import ContainerCredentials

    if env.get(local_var):
        raise ConfigError(f"{local_var} names a local folder, which the cloud loses when a task stops; the {what} is the "
                          f"S3 bucket {bucket_var}. Remove {local_var}; nothing was started")
    bucket = env.get(bucket_var)
    if not bucket:
        raise ConfigError(f"the cloud needs {bucket_var} (an S3 bucket with Object Lock) for the {what}; nothing was "
                          "started")
    region = env.get("AWS_REGION")
    if not region:
        raise ConfigError(f"the cloud needs AWS_REGION for {bucket_var}; nothing was started")
    return S3ObjectLockEvidenceStore(endpoint="https" + f"://s3.{region}.amazonaws.com", bucket=bucket, region=region,
                                     credentials=ContainerCredentials(env=env))


def evidence_store_only(cfg, env: Mapping[str, str]):
    """The evidence store alone, for a job that stores files there and uses no other bucket (the records export worker): it
    reads CONSENTVAULT_EVIDENCE_BUCKET and nothing about the archive or the lifecycle ledger. Self-host: the local folder."""
    from .providers.evidence import LocalAppendOnlyEvidenceStore

    if cfg.db_auth == "iam":
        return _bucket_store(env, "CONSENTVAULT_EVIDENCE_BUCKET", "CONSENTVAULT_EVIDENCE_DIR", "evidence store")
    return LocalAppendOnlyEvidenceStore(_need(env, "CONSENTVAULT_EVIDENCE_DIR"))


def cloud_stores(cfg, env: Mapping[str, str]):
    """(evidence store, archive store, lifecycle ledger store). Cloud (db_auth = iam): three S3 buckets with Object Lock
    on the task role, and a local folder setting is refused. Self-host: the local append-only folders."""
    from .providers.evidence import LocalAppendOnlyEvidenceStore

    if cfg.db_auth == "iam":
        return (_bucket_store(env, "CONSENTVAULT_EVIDENCE_BUCKET", "CONSENTVAULT_EVIDENCE_DIR", "evidence store"),
                _bucket_store(env, "CONSENTVAULT_ARCHIVE_BUCKET", "CONSENTVAULT_ARCHIVE_DIR", "archive store"),
                _bucket_store(env, "CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET", "CONSENTVAULT_LIFECYCLE_LEDGER_DIR",
                              "lifecycle ledger"))
    archive = _need(env, "CONSENTVAULT_ARCHIVE_DIR")
    return (LocalAppendOnlyEvidenceStore(_need(env, "CONSENTVAULT_EVIDENCE_DIR")), LocalAppendOnlyEvidenceStore(archive),
            LocalAppendOnlyEvidenceStore(archive + "/lifecycle"))


def build_cloud(cfg, env: Mapping[str, str]):
    """Everything the server needs, or a ConfigError naming the first thing missing. Edge keys are checked first."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from . import api, db, dbclock
    from .billing.stripe_client import HttpStripeClient
    from .cloud_startup import build_admin_app, build_routes
    from .sync.connectors.webhook import EgressTransport
    from .tenancy.erasure import LifecycleLedger
    from .tenancy.tokens import mint_org_token
    from .providers.identity import HttpJwksFetcher, OIDCIdentityProvider
    from .providers.plugins import load_key_provider, resolve_object
    from .route_wiring import Authenticator
    from .tenancy.crypto import TenantCrypto
    from .tenancy.keys_adapter import CustodyKeyAdapter
    from .tenancy.oauth import AccessTokenSigner
    from .tenancy.pipeline import ReceiptSigner
    from .tenancy.session import require_edge_keys
    from .confirm import wiring

    require_edge_keys(cfg)
    confirm_settings = wiring.confirmation_settings(env)  # half configured refuses the start here, before anything is built
    custody = load_key_provider(cfg.key_provider, env=env)
    token_key = _token_key(env)
    connect = db.connect_factory(cfg)
    identity = OIDCIdentityProvider(issuer=_need(env, ENV_ISSUER), audience=_need(env, ENV_AUDIENCE),
                                    jwks_fetcher=HttpJwksFetcher(_need(env, ENV_JWKS)),
                                    audience_claim=env.get(ENV_AUDIENCE_CLAIM) or "aud",
                                    clock=dbclock.datetime_clock(connect))
    mailer_spec = _plugin_spec(env, "CONSENTVAULT_MAILER")
    mailer_cls = resolve_object(mailer_spec)
    mailer = mailer_cls.from_environment(env)

    def seed(name: str) -> ed25519.Ed25519PrivateKey:
        try:
            return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(_read(env, name)))
        except ValueError as exc:
            raise ConfigError(f"{name} is not a hex Ed25519 seed (32 bytes): {describe(exc)}") from exc

    access_url = _need(env, "CONSENTVAULT_TOKEN_ENDPOINT_URL")
    access = AccessTokenSigner(seed("CONSENTVAULT_ACCESS_KEY_FILE"), key_id="access-1", issuer=access_url.rsplit("/v1/", 1)[0])
    receipts = ReceiptSigner(seed("CONSENTVAULT_RECEIPT_KEY_FILE"), key_id="receipt-1")
    cursor_key = bytes.fromhex(_read(env, "CONSENTVAULT_CURSOR_KEY_FILE"))
    store, archive_store, ledger_store = cloud_stores(cfg, env)
    owner_connect = lambda: db.connect(cfg.require_operator_dsn())  # noqa: E731
    crypto = TenantCrypto(CustodyKeyAdapter.from_database(custody, owner_connect, token_key))  # fingerprint secret and display key come from the database
    clock = dbclock.epoch_clock(connect)  # ONE clock (confirmations.md section 13): the admin app and the confirmation service
    egress = EgressTransport(_need(env, ENV_EGRESS_URL), _read(env, ENV_EGRESS_SECRET_FILE))  # sync pushes, the link host's DNS and probe
    confirmations = wiring.build_service(env, connect=connect, token_key=token_key, custody=custody, clock=clock, egress=egress)
    admin_app = build_admin_app(cfg, identity=identity, token_key=token_key, connect=connect, owner_connect=owner_connect,
                                custody=custody, mailer=mailer, evidence_store=store, crypto=crypto, clock=clock,
                                confirmations=confirmations)
    auth = Authenticator(connect=connect, access_tokens=access, identity=None, operators={})
    signer = resolve_object(_plugin_spec(env, "CONSENTVAULT_EVIDENCE_SIGNER")).from_environment(env)
    notifier = resolve_object(_plugin_spec(env, "CONSENTVAULT_NOTIFIER")).from_environment(env)
    stripe = HttpStripeClient(_read(env, "CONSENTVAULT_STRIPE_SECRET_KEY_FILE"))
    routes = build_routes(
        admin_app=admin_app, auth=auth, connect=connect, owner_connect=owner_connect, token_key=token_key, crypto=crypto,
        custody=custody, evidence_store=store, archive_store=archive_store, ledger=LifecycleLedger(ledger_store, clock=dbclock.datetime_clock(connect)),
        signer=signer, notifier=notifier, stripe=stripe, webhook_secret=_read(env, "CONSENTVAULT_STRIPE_WEBHOOK_SECRET_FILE"),
        link_secret=bytes.fromhex(_read(env, "CONSENTVAULT_LINK_SECRET_FILE")),
        mint_token=lambda o, sc: mint_org_token(token_key, o, sc, credential_id=None),
        transport=egress, region=cfg.default_region,
        confirmations=confirmations, confirmations_api_base=confirm_settings[0] if confirm_settings else None)
    return api.CloudApiSettings(
        dsn=cfg.require_dsn(), token_key=token_key, access_tokens=access, receipts=receipts, crypto=crypto,
        evidence_store=store, token_endpoint_url=access_url, cursor_key=cursor_key, routes=routes,
        portal_caller=auth.billing_caller, region=cfg.default_region,
        raw_post_inline_limit_bytes=cfg.raw_post_inline_limit_bytes, raw_post_unusual_size_bytes=cfg.raw_post_unusual_size_bytes)


def _serve_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)


def _run(args, cfg) -> int:
    from . import api

    from . import metrics

    settings = build_cloud(cfg, os.environ)
    server = api.make_cloud_server(settings, args.host, args.port)
    print(json.dumps({"serving": f"{args.host}:{args.port}", "mode": "cloud"}), flush=True)
    # One summary of the capture and gate metrics every minute, zeros included (consentvault.metrics).
    stop_ticker = metrics.start_ticker()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return cli.EXIT_OK
    finally:
        server.server_close()
        stop_ticker()
    return cli.EXIT_OK


cli.register("serve-cloud", "run the multi-tenant API with the portal's sign-in", _run, _serve_args)
