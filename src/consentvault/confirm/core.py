"""What every part of the confirmation service shares: the clock, the tenant transaction, the keys, sealing, the audit row,
the alarms and the small reads (settings, registration, link host, the live sending account).

The service holds no standing database connection. Each unit of work mints a short tenant token for one organization (the
token key is the API's own) and runs in one transaction on a fresh runtime-role connection, so row security binds every read
and write to that organization.
"""

from __future__ import annotations

import json
from .. import safelog
import random
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import psycopg
from psycopg.types.json import Jsonb

from ..providers.errors import KeyProviderError as CustodyKeyError
from ..tenancy import audit
from ..tenancy import crypto as tc
from ..tenancy.admin_base import ApiError
from ..tenancy.crypto import TenantCrypto
from ..tenancy.errors import KeyProviderError as TenantKeyError
from ..tenancy.keys_adapter import CustodyKeyAdapter
from ..tenancy.keys_protocol import WrappedKey
from ..tenancy.tokens import TokenKey, mint_org_token, org_transaction
from . import basis, texts
from .providers import DohResolver, ProviderError, default_providers

log = safelog.get("consentvault.confirm")

KEY_ERRORS = (CustodyKeyError, TenantKeyError)
SERVICE_SCOPES = ("capture_verified", "gate_read", "worker:confirmations")
TOKEN_TTL_SECONDS = 300
STOP_CHANNELS = ("sms", "voice", "artificial_voice")
ALL_CHANNELS = ("sms", "voice", "artificial_voice", "email")
SECRET_FIELD = {"twilio": "api_key_secret", "ses": "secret", "postmark": "server_token"}
MAX_WRAPPED_SECRET_BYTES = 64
MIN_SECRET_BYTES = 1
INBOUND_NOT_FOUND = {"error": "not_found"}
SYSTEM_REPLIES = "Confirmation replies"
SYSTEM_STOP_PAGE = "Email stop page"
RECORDED_BY = "confirmations"


@dataclass
class Reply:
    """What the inbound door and the public pages answer: a status, a JSON payload or raw bytes, and any headers."""

    status: int
    payload: Optional[dict] = None
    raw: Optional[bytes] = None
    headers: dict = field(default_factory=dict)


class _WrappedSecretLoader:
    """Hands ``CustodyKeyAdapter`` an organization's wrapped fingerprint secret or display key, read through the one
    owner-rights door (``confirmation_wrapped_secret``) under this service's own worker scope."""

    def __init__(self, service: "Core", kind: str):
        self._service, self._kind = service, kind
        self._held: dict[uuid.UUID, bytes] = {}

    def __call__(self, org_id) -> bytes:
        org = uuid.UUID(str(org_id))
        held = self._held.get(org)
        if held is not None:
            return held
        try:
            with self._service.tx(org, scopes=("worker:confirmations",)) as conn:
                row = conn.execute("SELECT consentvault.confirmation_wrapped_secret(%s) AS w", (self._kind,)).fetchone()
        except psycopg.Error as exc:
            raise TenantKeyError(f"the {self._kind} secret of organisation {org} could not be read: {type(exc).__name__}") from exc
        if row is None or row["w"] is None:
            raise TenantKeyError(f"no wrapped {self._kind} secret is stored for organisation {org}")
        self._held[org] = bytes(row["w"])
        return self._held[org]

    def forget(self, org_id) -> None:
        self._held.pop(uuid.UUID(str(org_id)), None)


class Core:
    def __init__(self, connect: Callable[[], psycopg.Connection], token_key: TokenKey, custody, providers: Optional[dict] = None,
                 dns=None, clock: Callable[[], float] = time.time, jitter: Optional[Callable[[], float]] = None, *,
                 api_base: str = "https://api.consentvault.ai", edge_cname: str = "edge.consentvault.ai"):
        self._connect = connect
        self._key = token_key
        self._custody = custody
        self._providers = providers if providers is not None else default_providers()
        self._dns = dns if dns is not None else DohResolver()
        self._clock = clock
        self._jitter = jitter if jitter is not None else (lambda: random.uniform(0, 0.2))
        self._api_base = api_base.rstrip("/")
        self._edge_cname = edge_cname
        self._crypto: Optional[TenantCrypto] = None

    # ---- time ----------------------------------------------------------------------------------------------------------
    def _dt(self, now: Optional[float] = None) -> datetime:
        """The injected clock (epoch seconds) as a UTC datetime; ``now`` overrides it."""
        return datetime.fromtimestamp(self._clock() if now is None else now, tz=timezone.utc)

    def _when(self, conn, now: Optional[float] = None) -> datetime:
        """The time a decision is judged on: the database's clock, read inside the transaction that decides. A pinned time (epoch
        seconds) is for tests and replays only."""
        if now is not None:
            return datetime.fromtimestamp(now, tz=timezone.utc)
        from . import sender
        return sender.db_now(conn)

    # ---- the tenant transaction ----------------------------------------------------------------------------------------
    def _token(self, org, scopes=SERVICE_SCOPES) -> str:
        return mint_org_token(self._key, org, scopes, credential_id=None, ttl_seconds=TOKEN_TTL_SECONDS)

    @contextmanager
    def tx(self, org, scopes=SERVICE_SCOPES):
        """A connection inside one transaction of ``org``, on this service's worker token."""
        conn = self._connect()
        try:
            with org_transaction(conn, self._token(org, scopes)):
                yield conn
        finally:
            conn.close()

    _ORG_LISTS = {"confirmation_org_ids": "SELECT confirmation_org_ids AS org FROM consentvault.confirmation_org_ids()",
                  "confirmation_work_orgs": "SELECT confirmation_work_orgs AS org FROM consentvault.confirmation_work_orgs()"}

    def _org_list(self, function: str) -> list[uuid.UUID]:
        """Organization ids from one of the owner-rights lists: every organization, or those with a message waiting."""
        conn = self._connect()
        try:
            return [r["org"] for r in conn.execute(self._ORG_LISTS[function]).fetchall()]
        finally:
            conn.close()

    # ---- keys ----------------------------------------------------------------------------------------------------------
    @property
    def crypto(self) -> TenantCrypto:
        if self._crypto is None:
            self._crypto = TenantCrypto(CustodyKeyAdapter(self._custody, _WrappedSecretLoader(self, "fingerprint"),
                                                          _WrappedSecretLoader(self, "display")))
        return self._crypto

    def _seal(self, org, record_id: str, column: str, value) -> bytes:
        """Seal under the organization's display key (itself wrapped by the organization key, so it rotates and is destroyed
        with it)."""
        return tc.encrypt_field(self.crypto.display_key(org), org, record_id, column, value)

    def _unseal(self, org, record_id: str, column: str, blob) -> str:
        return tc.decrypt_text(self.crypto.display_key(org), org, record_id, column, bytes(blob))

    def _contact_key(self, conn, org, fp: str) -> Optional[bytes]:
        """The contact's data key, or None when the contact was erased. A key that cannot be opened raises."""
        held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (fp,)).fetchone()
        if held is None:
            return None
        return self.crypto.open_contact_key(org, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))

    def _record_of(self, conn, fp: str):
        """The active record id of a contact, through the one owner-rights door (the service holds no read scope on records)."""
        return conn.execute("SELECT consentvault.confirmation_record_of(%s) AS r", (fp,)).fetchone()["r"]

    def _contact_of_event(self, conn, org, event_id) -> tuple[str, str, bytes]:
        """(kind, normalised contact point, data key) of the contact an event is about; raises when erased."""
        row = basis.event_like(conn, org, event_id)
        if row is None:
            raise ApiError("not_found", "no such event")
        key = self._contact_key(conn, org, row["contact_fp"])
        if key is None:
            raise ApiError("contact_already_erased", "that contact was erased")
        return row["contact_kind"], tc.decrypt_text(key, org, str(event_id), "contact_norm", bytes(row["contact_ct"])), key

    # ---- audit and alarms ----------------------------------------------------------------------------------------------
    def _audit(self, conn, action: str, target_kind: str, target_id: Optional[str] = None, *, detail: Optional[dict] = None,
               reason: Optional[str] = None) -> None:
        audit.append(conn, actor_kind="system", actor_id=RECORDED_BY, action=action, target_kind=target_kind,
                     target_id=target_id, reason=reason, request_id="confirmations-" + uuid.uuid4().hex[:16], detail=detail)

    def _alarm_raise(self, conn, kind: str, detail: dict, at: datetime) -> None:
        conn.execute("SELECT consentvault.confirmation_alarm_raise(%s, %s, %s)", (kind, Jsonb(detail), at))

    def _alarm_clear(self, conn, kind: str, at: datetime) -> None:
        conn.execute("SELECT consentvault.confirmation_alarm_clear(%s, %s)", (kind, at))

    def raise_alarm(self, org_id, kind: str, detail: Optional[dict] = None) -> None:
        """Open an alarm of the organization (one open row per kind). The only writer of the confirmation alarms."""
        with self.tx(org_id) as conn:
            self._alarm_raise(conn, kind, detail or {}, self._when(conn))

    def clear_alarm(self, org_id, kind: str) -> None:
        with self.tx(org_id) as conn:
            self._alarm_clear(conn, kind, self._when(conn))

    # ---- small reads ---------------------------------------------------------------------------------------------------
    def _system_source(self, conn, name: str) -> uuid.UUID:
        return conn.execute("SELECT consentvault.confirmation_system_source(%s) AS sid", (name,)).fetchone()["sid"]

    def _settings_row(self, conn) -> Optional[dict]:
        return conn.execute("SELECT * FROM consentvault.confirmation_settings WHERE org_id = (SELECT consentvault.current_org())"
                            " ORDER BY version DESC LIMIT 1").fetchone()

    def _registration_row(self, conn) -> Optional[dict]:
        return conn.execute("SELECT * FROM consentvault.confirmation_registration WHERE org_id = (SELECT consentvault.current_org())"
                            ).fetchone()

    def _registration_current(self, reg: Optional[dict]) -> bool:
        """Marked, and marked for the fixed text this process carries (read from the module at each call)."""
        return bool(reg and reg["status"] == "marked" and reg["samples_statement_version"] == texts.FIXED_TEXT_VERSION)

    def _link_host_row(self, conn) -> Optional[dict]:
        return conn.execute("SELECT * FROM consentvault.confirmation_link_host WHERE org_id = (SELECT consentvault.current_org())"
                            ).fetchone()

    def _live_account(self, conn, channel: str) -> Optional[dict]:
        return conn.execute(
            "SELECT * FROM (SELECT org_id, account_id, channel, provider, status, from_email, from_display_name, sender_id,"
            " number_hint, sender_ct, inbound_key, inbound_url, provider_replies, inbound_verified_at, refusal_count,"
            " last_refusal_code, created_at, disconnected_at FROM consentvault.sending_account) a"
            " WHERE a.org_id = (SELECT consentvault.current_org()) AND a.channel = %s AND a.status <> 'disconnected'",
            (channel,)).fetchone()

    def _org_status(self, conn) -> str:
        return conn.execute("SELECT status FROM consentvault.organization WHERE org_id = (SELECT consentvault.current_org())"
                            ).fetchone()["status"]

    def _org_channels(self, conn) -> set[str]:
        return {r["channel"] for r in conn.execute("SELECT channel FROM consentvault.channel WHERE org_id ="
                                                   " (SELECT consentvault.current_org())")}

    def _stop_channels(self, conn) -> list[str]:
        have = self._org_channels(conn)
        return [c for c in STOP_CHANNELS if c in have] or ["sms"]

    # ---- sealed provider credentials -----------------------------------------------------------------------------------
    def _seal_credentials(self, org, provider: str, creds: dict, account_id: str) -> tuple[bytes, bytes, Optional[bytes]]:
        """(credentials_ct, credential_ids_ct, auth_token_ct). The provider's one secret is wrapped by the organization key
        itself (so only the key custody opens it; a short one is padded to the custody's 16-byte minimum behind a length byte);
        the rest of the credentials, the non-secret ids, are sealed under the display key; a Twilio auth token is wrapped on its
        own and used only to check request signatures."""
        field_name = SECRET_FIELD[provider]
        secret = str(creds[field_name]).encode("utf-8")
        if not MIN_SECRET_BYTES <= len(secret) <= MAX_WRAPPED_SECRET_BYTES - 1:
            raise ApiError("validation_failed", "a provider secret is 1 to 63 bytes",
                           {"credentials": f"{field_name} must be 1 to {MAX_WRAPPED_SECRET_BYTES - 1} bytes"})
        rest = {k: v for k, v in creds.items() if k not in (field_name, "auth_token")}
        wrapped = self._custody.wrap(str(org), bytes([len(secret)]) + secret + b"\x00" * max(0, 15 - len(secret)))
        ids = self._seal(org, account_id, "credential_ids_ct", json.dumps(rest, sort_keys=True))
        token = creds.get("auth_token")
        token_ct = None
        if token:
            raw = str(token).encode("utf-8")
            if not 16 <= len(raw) <= MAX_WRAPPED_SECRET_BYTES:
                raise ApiError("validation_failed", "the auth token is 16 to 64 bytes", {"credentials": "auth_token length"})
            token_ct = self._custody.wrap(str(org), raw)
        return wrapped, ids, token_ct

    def _open_credentials(self, conn, org, account: dict) -> dict:
        """The credentials to call the provider with. Never includes the Twilio auth token."""
        row = conn.execute("SELECT * FROM consentvault.confirmation_account_secrets(%s)", (account["account_id"],)).fetchone()
        if row is None or row["credentials_ct"] is None or row["credential_ids_ct"] is None:
            raise ProviderError("account", "credentials_deleted")
        creds = json.loads(self._unseal(org, str(account["account_id"]), "credential_ids_ct", row["credential_ids_ct"]))
        framed = self._custody.unwrap(str(org), bytes(row["credentials_ct"]))
        creds[SECRET_FIELD[account["provider"]]] = framed[1:1 + framed[0]].decode("utf-8")
        sid = conn.execute("SELECT account_sid FROM consentvault.sending_account WHERE org_id = %s AND account_id = %s",
                           (org, account["account_id"])).fetchone()["account_sid"]
        if sid:  # Twilio's API address carries the account id; it is not a secret and is kept in the clear
            creds["account_sid"] = sid
        return creds

    def _open_auth_token(self, conn, org, account_id) -> Optional[str]:
        row = conn.execute("SELECT * FROM consentvault.confirmation_account_secrets(%s)", (account_id,)).fetchone()
        if row is None or row["auth_token_ct"] is None:
            return None
        return self._custody.unwrap(str(org), bytes(row["auth_token_ct"])).decode("utf-8")

    def _sender_spec(self, org, account: dict) -> dict:
        return json.loads(self._unseal(org, str(account["account_id"]), "sender_ct", account["sender_ct"]))
