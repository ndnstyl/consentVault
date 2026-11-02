"""Adapter from the providers' org-key custody (``consentvault.providers.keys.KeyProvider``) to the three methods
the field-encryption layer needs (``tenancy.keys_protocol.KeyProvider``).

The providers keep one wrap key per organisation in versions (``rotate_org_key``); a wrapped data key carries the
version it was wrapped under (``providers.keys.wrapped_version``), which is the matching ``consentvault.org_key`` row.
A provider that has never rotated wraps under version 1, in the format it always had. The organisation's fingerprint secret is an independent random 32-byte
secret, generated once at organisation creation (``new_fingerprint_secret``), stored wrapped by the org key wherever
the caller keeps it, and handed back through ``load_wrapped_fingerprint_secret``. It is never derived from another
key. When the org key is destroyed the fingerprint secret becomes unreadable with everything else.
"""

from __future__ import annotations

import os
import threading
import uuid
from typing import Callable, Optional

import psycopg

from ..providers.errors import KeyProviderError as CustodyKeyError
from ..providers.keys import KeyProvider as CustodyProvider, wrapped_version
from ..lengths import is_bytes_of_len
from .errors import KeyProviderError
from .keys_protocol import WrappedKey

ORG_KEY_VERSION = 1
FINGERPRINT_SECRET_BYTES = 32
# the only scope the loader's token carries: it opens nothing but the organisation's own row of org_fingerprint_secret
FINGERPRINT_LOADER_SCOPE = "worker:fingerprint_secret"
FINGERPRINT_LOADER_TTL = 30
# the display key (records.md section 8) is stored and read the same way, under its own scope and table
DISPLAY_LOADER_SCOPE = "worker:display_key"
DISPLAY_KEY_BYTES = 32


class DatabaseFingerprintSecretLoader:
    """Reads ``consentvault.org_fingerprint_secret`` (migration 0005) for ``CustodyKeyAdapter``.

    Only the operator console's role (consentvault_console, migration 0019) holds a grant on that table besides the
    owner, and row-level security binds it, so each read enters the organisation with a 30-second token naming it
    (``owner_connect`` returns an operator console connection, idle and autocommit; never the schema owner, which cannot
    log in; ``token_key`` is the vault's tenant token key). The secret is never rotated and the row is append-only,
    so the wrapped bytes are kept in memory once read; they stay unreadable without the org key, and destroying the org
    key makes them unreadable everywhere. A key rotation re-wraps the row under the new version; ``forget`` drops the held
    copy so the next read takes the re-wrapped bytes. A missing row or a failed read raises ``KeyProviderError``.
    """

    _SCOPE = FINGERPRINT_LOADER_SCOPE
    _SQL = ("SELECT wrapped FROM consentvault.org_fingerprint_secret"
            " WHERE org_id = (SELECT consentvault.current_org())")
    _WHAT = "fingerprint secret"

    def __init__(self, owner_connect: Callable[[], psycopg.Connection], token_key) -> None:
        if not callable(owner_connect):
            raise KeyProviderError("owner_connect must be callable")
        self._connect = owner_connect
        self._key = token_key
        self._held: dict[uuid.UUID, bytes] = {}
        self._lock = threading.Lock()

    def __call__(self, org_id: uuid.UUID) -> bytes:
        from .tokens import mint_org_token, org_transaction

        org = uuid.UUID(str(org_id))
        with self._lock:
            held = self._held.get(org)
        if held is not None:
            return held
        try:
            token = mint_org_token(self._key, org, [self._SCOPE], credential_id=None,
                                   ttl_seconds=FINGERPRINT_LOADER_TTL)
            with self._connect() as conn, org_transaction(conn, token):
                row = conn.execute(self._SQL).fetchone()
        except psycopg.Error as exc:
            raise KeyProviderError(f"the {self._WHAT} of organisation {org} could not be read:"
                                   f" {type(exc).__name__}") from exc
        if row is None:
            raise KeyProviderError(f"no wrapped {self._WHAT} is stored for organisation {org}")
        wrapped = bytes(row["wrapped"])
        with self._lock:
            self._held[org] = wrapped
        return wrapped

    def forget(self, org_id: uuid.UUID) -> None:
        with self._lock:
            self._held.pop(uuid.UUID(str(org_id)), None)


class DatabaseDisplayKeyLoader(DatabaseFingerprintSecretLoader):
    """Reads ``consentvault.org_display_key`` (migration 0044) for ``CustodyKeyAdapter``, exactly as the fingerprint secret
    is read, under the token scope ``worker:display_key`` (the table's read policy admits no other)."""

    _SCOPE = DISPLAY_LOADER_SCOPE
    _SQL = "SELECT wrapped FROM consentvault.org_display_key WHERE org_id = (SELECT consentvault.current_org())"
    _WHAT = "display key"


class CustodyKeyAdapter:
    """Implements ``tenancy.keys_protocol.KeyProvider`` over a providers ``KeyProvider``. Beyond that protocol it hands out
    the organisation's display key (``display_key``), which seals the masked contact, name and company of a record."""

    def __init__(self, custody: CustodyProvider, load_wrapped_fingerprint_secret: Callable[[uuid.UUID], bytes],
                 load_wrapped_display_key: Optional[Callable[[uuid.UUID], bytes]] = None):
        if not isinstance(custody, CustodyProvider):
            raise KeyProviderError("custody must be a consentvault.providers.keys.KeyProvider")
        if not callable(load_wrapped_fingerprint_secret):
            raise KeyProviderError("load_wrapped_fingerprint_secret must be callable")
        if load_wrapped_display_key is not None and not callable(load_wrapped_display_key):
            raise KeyProviderError("load_wrapped_display_key must be callable")
        self._custody = custody
        self._load_fp = load_wrapped_fingerprint_secret
        self._load_display = load_wrapped_display_key

    @classmethod
    def from_database(cls, custody: CustodyProvider, owner_connect: Callable[[], psycopg.Connection],
                      token_key) -> "CustodyKeyAdapter":
        """The production wiring: the fingerprint secret comes from ``consentvault.org_fingerprint_secret`` and the display
        key from ``consentvault.org_display_key``."""
        return cls(custody, DatabaseFingerprintSecretLoader(owner_connect, token_key),
                   DatabaseDisplayKeyLoader(owner_connect, token_key))

    @property
    def provable_destruction(self) -> bool:
        return self._custody.provable_destruction

    def new_fingerprint_secret(self, org_id: uuid.UUID) -> bytes:
        """Generate the organisation's fingerprint secret; returns it wrapped by the org key, for the caller to store."""
        return self._custody.wrap(str(org_id), os.urandom(FINGERPRINT_SECRET_BYTES))

    def new_display_key(self, org_id: uuid.UUID) -> bytes:
        """Generate the organisation's display key; returns it wrapped by the org key, for the caller to store."""
        return self._custody.wrap(str(org_id), os.urandom(DISPLAY_KEY_BYTES))

    @property
    def custody(self) -> CustodyProvider:
        return self._custody

    def wrap_data_key(self, org_id: uuid.UUID, data_key: bytes) -> WrappedKey:
        blob = self._custody.wrap(str(org_id), data_key)
        return WrappedKey(blob, wrapped_version(blob))

    def unwrap_data_key(self, org_id: uuid.UUID, wrapped: WrappedKey) -> bytes:
        held = wrapped_version(wrapped.ciphertext)
        if wrapped.key_version != held:
            raise KeyProviderError(f"the contact key is recorded under key version {wrapped.key_version} but its wrap "
                                   f"was made under version {held}")
        return self._custody.unwrap(str(org_id), wrapped.ciphertext)

    def fingerprint_secret(self, org_id: uuid.UUID) -> bytes:
        wrapped = self._load_fp(org_id)
        if not isinstance(wrapped, (bytes, bytearray)) or not wrapped:
            raise KeyProviderError(f"no wrapped fingerprint secret is stored for organisation {org_id}")
        try:
            secret = self._custody.unwrap(str(org_id), bytes(wrapped))
        except CustodyKeyError:
            forget = getattr(self._load_fp, "forget", None)
            if forget is None:
                raise
            forget(org_id)  # a rotation re-wrapped it and destroyed the version held in memory: read the row again
            secret = self._custody.unwrap(str(org_id), bytes(self._load_fp(org_id)))
        if not is_bytes_of_len(secret, FINGERPRINT_SECRET_BYTES):
            raise KeyProviderError("the stored fingerprint secret is not 32 bytes")
        return secret

    def display_key(self, org_id: uuid.UUID) -> bytes:
        """The organisation's 32-byte display key, unwrapped on each call (no key is kept in memory)."""
        if self._load_display is None:
            raise KeyProviderError("this key adapter was built without a display key loader")
        wrapped = self._load_display(org_id)
        if not isinstance(wrapped, (bytes, bytearray)) or not wrapped:
            raise KeyProviderError(f"no wrapped display key is stored for organisation {org_id}")
        try:
            key = self._custody.unwrap(str(org_id), bytes(wrapped))
        except CustodyKeyError:
            forget = getattr(self._load_display, "forget", None)
            if forget is None:
                raise
            forget(org_id)  # a rotation re-wrapped it and destroyed the version held in memory: read the row again
            key = self._custody.unwrap(str(org_id), bytes(self._load_display(org_id)))
        if not is_bytes_of_len(key, DISPLAY_KEY_BYTES):
            raise KeyProviderError("the stored display key is not 32 bytes")
        return key
