"""Where the multi-tenant portal API is put together at startup. The admin app is built here and nowhere else in production,
so the portal edge's assertion keys are required at real startup: a deployment without them refuses to start (ConfigError)
rather than serve sign-in that cannot know how anyone signed in."""

from __future__ import annotations

from .tenancy.admin_routes import AdminApp
from . import dbclock
from .tenancy.session import session_minter_from_config


def build_admin_app(config, *, identity, token_key, connect, owner_connect, custody, mailer, **extra) -> AdminApp:
    sessions = session_minter_from_config(config, identity, token_key, clock=dbclock.datetime_clock(connect))
    return AdminApp(connect=connect, owner_connect=owner_connect, token_key=token_key, sessions=sessions, custody=custody,
                    mailer=mailer, **extra)


# Routes the server itself answers (api.py), not mounted route objects. The dashboard calls this one.
BUILT_IN_ROUTES = frozenset({("POST", "/v1/proof")})


def build_routes(*, admin_app, auth, connect, owner_connect, token_key, crypto, custody, evidence_store, archive_store, ledger,
                 signer, notifier, stripe, webhook_secret, link_secret, mint_token, transport=None, region=None, confirmations=None,
                 confirmations_api_base=None) -> tuple:
    """Every route family the dashboard uses, in one place: admin (sign-in, members, configuration), systems and deliveries,
    evidence packages, billing, and erasure / offboarding / legal holds. serve-cloud mounts exactly this tuple; a test compares it
    with the routes the dashboard's API client calls. With the confirmation service on (``confirm.wiring``), its door (the
    provider's inbound posts and the two public pages) is mounted last."""
    from .billing.routes import BillingRoutes
    from .evidence import ExportService
    from .route_wiring import AdminRoutes, ExportRouteAdapter, SyncRouteAdapter, TwentyWebhookAdapter, lifecycle_routes
    from .sync.connectors.twenty_receiver import TwentyReceiver
    from .sync.routes import SyncRoutes
    from .tenancy.lifecycle_routes import LifecycleApp

    exports = ExportService(connect=connect, mint_token=mint_token, crypto=crypto, signer=signer, store=evidence_store,
                            link_secret=link_secret, region=region)
    lifecycle = LifecycleApp(connect=connect, owner_connect=owner_connect, token_key=token_key, crypto=crypto, custody=custody,
                             ledger=ledger, store=archive_store, signer=signer, notifier=notifier, export_cache=evidence_store,
                             region=region, links=exports)
    routes = (AdminRoutes(admin_app, auth), SyncRouteAdapter(SyncRoutes(connect, crypto, custody=custody, transport=transport, mint_token=mint_token), auth, token_key),
            ExportRouteAdapter(exports, auth),
            BillingRoutes(connect=connect, mint_token=mint_token, client=stripe, webhook_secret=webhook_secret),
            lifecycle_routes(lifecycle, auth),
            TwentyWebhookAdapter(TwentyReceiver(connect, crypto, custody, token_key, region=region)))
    if confirmations is None:
        return routes
    from .confirm.wiring import ConfirmationDoor

    if not confirmations_api_base:
        from .errors import ConfigError
        raise ConfigError("the confirmation door needs the public API base it was configured with; nothing was started")
    return routes + (ConfirmationDoor(confirmations, confirmations_api_base),)
