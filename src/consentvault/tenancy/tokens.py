"""Tenant tokens: the only thing row-level security trusts.

A token is ``v1.<key id>.<payload hex>.<hmac hex>``; the HMAC-SHA256 covers ``v1.<key id>.<payload hex>`` under a key
the database keeps in an owner-only table and the API holds in its secret store. ``consentvault.current_org()``
verifies the signature and expiry on every statement, so a token that is forged, expired or signed with a retired key
selects no rows. Tokens live at most 15 minutes; request tokens default to 5.

For the API lane:
- call ``SELECT consentvault.require_multi_tenant()`` once at startup and refuse to serve if it raises: in single
  mode a caller with no token is answered with the home organisation;
- mint a token only after the caller's credential is verified (``consentvault.resolve_credential``), with exactly
  the credential's scopes; capture-scoped tokens can write events but cannot read evidence rows back;
- background jobs never mint their own: they call ``consentvault.dispatch_orgs(job)`` as the worker role, the one
  intended cross-organisation path, and handle one organisation per transaction.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterable, Iterator

import psycopg

from .errors import TenantTokenError

MAX_TTL_SECONDS = 900
DEFAULT_TTL_SECONDS = 300
_KID = re.compile(r"^[a-z0-9_-]{1,32}$")
_SCOPE = re.compile(r"^[a-z][a-z0-9_:]{0,63}$")


@dataclass(frozen=True)
class TokenKey:
    key_id: str
    secret: bytes

    def __post_init__(self) -> None:
        if not _KID.match(self.key_id or ""):
            raise TenantTokenError("token key id must match ^[a-z0-9_-]{1,32}$")
        if not isinstance(self.secret, bytes) or len(self.secret) < 32:
            raise TenantTokenError("token key secret must be at least 32 bytes")

    def __repr__(self) -> str:  # the secret never reaches a log line
        return f"TokenKey(key_id={self.key_id!r}, secret=<{len(self.secret)} bytes>)"


def mint_org_token(
    key: TokenKey,
    org_id: uuid.UUID | str,
    scopes: Iterable[str],
    *,
    credential_id: str | None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: float | None = None,
) -> str:
    """Sign a tenant token for one organisation. Called only after the caller's credential has been verified."""
    try:
        org = uuid.UUID(str(org_id))
    except ValueError as exc:
        raise TenantTokenError(f"org_id is not a UUID: {exc}") from exc
    scope_list = sorted(set(scopes))
    if not scope_list or any(not _SCOPE.match(s) for s in scope_list):
        raise TenantTokenError("a tenant token needs at least one well-formed scope")
    if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise TenantTokenError(f"ttl_seconds must be 1 to {MAX_TTL_SECONDS}")
    issued = int(time.time() if now is None else now)
    payload = {"org": str(org), "scp": scope_list, "cid": credential_id, "iat": issued, "exp": issued + ttl_seconds,
               "jti": str(uuid.uuid4())}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8").hex()
    signed = f"v1.{key.key_id}.{body}"
    sig = hmac.new(key.secret, signed.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{signed}.{sig}"


@contextmanager
def org_transaction(conn: psycopg.Connection, token: str) -> Iterator[uuid.UUID]:
    """Open a transaction, enter the tenant the token names, and yield its org id.

    Refuses a connection that is not idle in autocommit mode: inside an outer transaction the block would be only a
    savepoint, and the setting would outlive it. The setting is cleared before the block ends, error or not, and is
    transaction-local besides, so nothing carries over to the next request on a pooled connection. A token the
    database refuses raises ``TenantTokenError``.
    """
    if not token:
        raise TenantTokenError("no tenant token given")
    if not conn.autocommit or conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
        raise TenantTokenError("org_transaction needs an idle connection in autocommit mode "
                               "(it must open the outermost transaction itself)")
    with conn.transaction():
        try:
            row = conn.execute("SELECT consentvault.enter_org(%s) AS org_id", (token,)).fetchone()
        except psycopg.errors.InvalidAuthorizationSpecification as exc:
            raise TenantTokenError("the database refused the tenant token") from exc
        except psycopg.Error as exc:
            raise TenantTokenError(f"could not enter the tenant: {type(exc).__name__}") from exc
        try:
            yield row["org_id"]
        finally:
            if conn.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS:
                conn.execute("SELECT set_config('consentvault.org_token', '', true)")
