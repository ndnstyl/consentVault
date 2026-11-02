"""Field encryption for multi-tenant rows.

- Each contact has its own random 256-bit data key, wrapped by the organisation key through a ``KeyProvider``.
  Deleting the wrapped key (one ``contact_key`` row) shreds every field below for that person.
- Fields are AES-256-GCM with a fresh 96-bit nonce. The additional data binds each ciphertext to its organisation,
  its record (event id, or the contact fingerprint for the salt) and its column, so a ciphertext copied to another
  organisation, row or column fails to decrypt.
- The payload hash is an HMAC under a key derived from the contact data key, so it cannot be tested against a
  guessed payload, and it dies with the key.
- Fingerprints are HMAC-SHA256 under the organisation's independent fingerprint secret, so the same phone number
  in two organisations has unrelated fingerprints. The secret is cached in memory for at most 15 minutes.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..safelog import describe
from .errors import FieldCryptoError, FieldDecryptError, KeyProviderError
from .keys_protocol import KeyProvider, WrappedKey

ENVELOPE_VERSION = 1
NONCE_BYTES = 12
DATA_KEY_BYTES = 32
MAX_FINGERPRINT_CACHE_SECONDS = 900
_ENC_INFO = b"consentvault/field-enc/v1"
_MAC_INFO = b"consentvault/payload-mac/v1"
_AAD_PREFIX = b"consentvault/field/v1"
_CONTACT_FP_DOMAIN = b"consentvault/contact-fp/v1"
_SUBJECT_FP_DOMAIN = b"consentvault/subject-fp/v1"


def _org(org_id: uuid.UUID | str) -> uuid.UUID:
    try:
        return uuid.UUID(str(org_id))
    except ValueError as exc:
        raise FieldCryptoError(f"org_id is not a UUID: {describe(exc)}") from exc


def _part(value: str, what: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise FieldCryptoError(f"{what} is required")
    if "\x00" in value:
        raise FieldCryptoError(f"{what} must not contain NUL")
    return value.encode("utf-8")


def field_aad(org_id: uuid.UUID | str, record_id: str, column: str) -> bytes:
    """The additional data of one field: organisation, record and column, NUL-separated (none may contain NUL)."""
    return b"\x00".join((_AAD_PREFIX, str(_org(org_id)).encode("ascii"), _part(str(record_id), "record_id"),
                         _part(column, "column")))


def _subkey(data_key: bytes, info: bytes) -> bytes:
    if not isinstance(data_key, bytes) or len(data_key) != DATA_KEY_BYTES:
        raise FieldCryptoError(f"a contact data key is {DATA_KEY_BYTES} bytes")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(data_key)


def encrypt_field(data_key: bytes, org_id: uuid.UUID | str, record_id: str, column: str, value: str | bytes) -> bytes:
    """Encrypt one field. Returns version byte || nonce || ciphertext-and-tag."""
    if isinstance(value, str):
        plain = value.encode("utf-8")
    elif isinstance(value, bytes):
        plain = value
    else:
        raise FieldCryptoError(f"field {column!r} must be str or bytes, not {type(value).__name__}")
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(_subkey(data_key, _ENC_INFO)).encrypt(nonce, plain, field_aad(org_id, record_id, column))
    return bytes([ENVELOPE_VERSION]) + nonce + ct


def decrypt_field(data_key: bytes, org_id: uuid.UUID | str, record_id: str, column: str, blob: bytes) -> bytes:
    """Decrypt one field; raises ``FieldDecryptError`` if the key, organisation, record or column does not match."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise FieldCryptoError(f"ciphertext of {column!r} must be bytes")
    blob = bytes(blob)
    if len(blob) < 1 + NONCE_BYTES + 16 or blob[0] != ENVELOPE_VERSION:
        raise FieldCryptoError(f"ciphertext of {column!r} is malformed or of an unknown envelope version")
    try:
        return AESGCM(_subkey(data_key, _ENC_INFO)).decrypt(
            blob[1:1 + NONCE_BYTES], blob[1 + NONCE_BYTES:], field_aad(org_id, record_id, column))
    except InvalidTag:
        raise FieldDecryptError(
            f"ciphertext of {column!r} failed authentication (wrong key, organisation, record or column)") from None


def decrypt_text(data_key: bytes, org_id: uuid.UUID | str, record_id: str, column: str, blob: bytes) -> str:
    raw = decrypt_field(data_key, org_id, record_id, column, blob)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FieldCryptoError(f"field {column!r} is not UTF-8 text: {describe(exc)}") from exc


def payload_mac(data_key: bytes, payload: bytes) -> str:
    """Keyed payload hash (hex): HMAC-SHA256 under a key derived from the contact data key."""
    if not isinstance(payload, bytes):
        raise FieldCryptoError("payload must be bytes")
    return hmac.new(_subkey(data_key, _MAC_INFO), payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class ContactKey:
    data_key: bytes
    wrapped: WrappedKey

    def __repr__(self) -> str:  # the data key never reaches a log line
        return f"ContactKey(key_version={self.wrapped.key_version}, data_key=<redacted>)"


class TenantCrypto:
    """Fingerprints and contact keys for every organisation, through one ``KeyProvider``."""

    def __init__(self, provider: KeyProvider, *, cache_seconds: int = MAX_FINGERPRINT_CACHE_SECONDS,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if not isinstance(provider, KeyProvider):
            raise KeyProviderError("provider does not implement KeyProvider (wrap_data_key, unwrap_data_key, "
                                   "fingerprint_secret)")
        if not isinstance(cache_seconds, int) or not 0 <= cache_seconds <= MAX_FINGERPRINT_CACHE_SECONDS:
            raise KeyProviderError(f"fingerprint cache must be 0 to {MAX_FINGERPRINT_CACHE_SECONDS} seconds")
        self._provider = provider
        self._cache_seconds = cache_seconds
        self._clock = clock
        self._fp_cache: dict[uuid.UUID, tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    # fingerprints -------------------------------------------------------------------------------------------------

    def _fingerprint_secret(self, org: uuid.UUID) -> bytes:
        now = self._clock()
        with self._lock:
            held = self._fp_cache.get(org)
            if held is not None and now - held[1] < self._cache_seconds:
                return held[0]
            self._fp_cache.pop(org, None)
        secret = self._call("fingerprint_secret", org)
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise KeyProviderError("fingerprint_secret must return at least 32 bytes")
        if self._cache_seconds:
            with self._lock:
                self._fp_cache[org] = (secret, now)
        return secret

    def forget(self, org_id: uuid.UUID | str | None = None) -> None:
        """Drop cached fingerprint secrets (one organisation, or all)."""
        with self._lock:
            if org_id is None:
                self._fp_cache.clear()
            else:
                self._fp_cache.pop(_org(org_id), None)

    def contact_fingerprint(self, org_id: uuid.UUID | str, contact_kind: str, contact_norm: str) -> str:
        org = _org(org_id)
        msg = b"\x00".join((_CONTACT_FP_DOMAIN, _part(contact_kind, "contact_kind"), _part(contact_norm, "contact")))
        return hmac.new(self._fingerprint_secret(org), msg, hashlib.sha256).hexdigest()

    def subject_fingerprint(self, org_id: uuid.UUID | str, subject_key: str) -> str:
        org = _org(org_id)
        msg = b"\x00".join((_SUBJECT_FP_DOMAIN, _part(subject_key, "subject_key")))
        return hmac.new(self._fingerprint_secret(org), msg, hashlib.sha256).hexdigest()

    # contact keys -------------------------------------------------------------------------------------------------

    def new_contact_key(self, org_id: uuid.UUID | str) -> ContactKey:
        org = _org(org_id)
        data_key = os.urandom(DATA_KEY_BYTES)
        wrapped = self._call("wrap_data_key", org, data_key)
        if not isinstance(wrapped, WrappedKey) or not isinstance(wrapped.ciphertext, bytes) \
                or not isinstance(wrapped.key_version, int) or wrapped.key_version < 1:
            raise KeyProviderError("wrap_data_key must return a WrappedKey with bytes and a key version >= 1")
        return ContactKey(data_key, wrapped)

    def open_contact_key(self, org_id: uuid.UUID | str, wrapped: WrappedKey) -> bytes:
        data_key = self._call("unwrap_data_key", _org(org_id), wrapped)
        if not isinstance(data_key, bytes) or len(data_key) != DATA_KEY_BYTES:
            raise KeyProviderError(f"unwrap_data_key must return {DATA_KEY_BYTES} bytes")
        return data_key

    def rewrap_contact_key(self, org_id: uuid.UUID | str, wrapped: WrappedKey) -> WrappedKey:
        """The same contact data key wrapped under the organisation's active key version (key rotation). The data key
        never changes, so nothing it encrypted changes."""
        org = _org(org_id)
        data_key = self.open_contact_key(org, wrapped)
        out = self._call("wrap_data_key", org, data_key)
        if not isinstance(out, WrappedKey) or not isinstance(out.ciphertext, bytes) \
                or not isinstance(out.key_version, int) or out.key_version < 1:
            raise KeyProviderError("wrap_data_key must return a WrappedKey with bytes and a key version >= 1")
        return out

    # display key ---------------------------------------------------------------------------------------------------

    def display_key(self, org_id: uuid.UUID | str) -> bytes:
        """The organisation's 32-byte display key (records.md section 8), which seals a record's masked contact, name and
        company with ``encrypt_field``. A provider without one raises ``KeyProviderError`` by name; none is invented."""
        key = self._call("display_key", _org(org_id))
        if not isinstance(key, bytes) or len(key) != DATA_KEY_BYTES:
            raise KeyProviderError(f"display_key must return {DATA_KEY_BYTES} bytes")
        return key

    def _call(self, method: str, *args):
        try:
            return getattr(self._provider, method)(*args)
        except KeyProviderError:
            raise
        except Exception as exc:  # any provider fault is named here and carried, never swallowed
            raise KeyProviderError(f"key provider {method} failed: {describe(exc)}") from exc
