"""Adapter from the providers' org-key custody (``consentvault.providers.keys.KeyProvider``) to the three methods
the field-encryption layer needs (``tenancy.keys_protocol.KeyProvider``).

The providers keep one wrap key per organisation and no versions, so every wrapped data key carries key version 1
(the matching ``consentvault.org_key`` row). The organisation's fingerprint secret is an independent random 32-byte
secret, generated once at organisation creation (``new_fingerprint_secret``), stored wrapped by the org key wherever
the caller keeps it, and handed back through ``load_wrapped_fingerprint_secret``. It is never derived from another
key. When the org key is destroyed the fingerprint secret becomes unreadable with everything else.
"""

from __future__ import annotations

import os
import uuid
from typing import Callable

from ..providers.keys import KeyProvider as CustodyProvider
from .errors import KeyProviderError
from .keys_protocol import WrappedKey

ORG_KEY_VERSION = 1
FINGERPRINT_SECRET_BYTES = 32


class CustodyKeyAdapter:
    """Implements ``tenancy.keys_protocol.KeyProvider`` over a providers ``KeyProvider``."""

    def __init__(self, custody: CustodyProvider, load_wrapped_fingerprint_secret: Callable[[uuid.UUID], bytes]):
        if not isinstance(custody, CustodyProvider):
            raise KeyProviderError("custody must be a consentvault.providers.keys.KeyProvider")
        if not callable(load_wrapped_fingerprint_secret):
            raise KeyProviderError("load_wrapped_fingerprint_secret must be callable")
        self._custody = custody
        self._load_fp = load_wrapped_fingerprint_secret

    @property
    def provable_destruction(self) -> bool:
        return self._custody.provable_destruction

    def new_fingerprint_secret(self, org_id: uuid.UUID) -> bytes:
        """Generate the organisation's fingerprint secret; returns it wrapped by the org key, for the caller to store."""
        return self._custody.wrap(str(org_id), os.urandom(FINGERPRINT_SECRET_BYTES))

    def wrap_data_key(self, org_id: uuid.UUID, data_key: bytes) -> WrappedKey:
        return WrappedKey(self._custody.wrap(str(org_id), data_key), ORG_KEY_VERSION)

    def unwrap_data_key(self, org_id: uuid.UUID, wrapped: WrappedKey) -> bytes:
        if wrapped.key_version != ORG_KEY_VERSION:
            raise KeyProviderError(f"key version {wrapped.key_version} is not held by this provider "
                                   f"(org keys here have version {ORG_KEY_VERSION} only)")
        return self._custody.unwrap(str(org_id), wrapped.ciphertext)

    def fingerprint_secret(self, org_id: uuid.UUID) -> bytes:
        wrapped = self._load_fp(org_id)
        if not isinstance(wrapped, (bytes, bytearray)) or not wrapped:
            raise KeyProviderError(f"no wrapped fingerprint secret is stored for organisation {org_id}")
        secret = self._custody.unwrap(str(org_id), bytes(wrapped))
        if len(secret) != FINGERPRINT_SECRET_BYTES:
            raise KeyProviderError("the stored fingerprint secret is not 32 bytes")
        return secret
