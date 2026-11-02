"""The minimal key interface the field-encryption layer needs.

Implementations live in ``consentvault.providers`` (KMS, OpenBao transit, local file). Every method raises
``KeyProviderError`` (or a subclass) on failure; none returns a default.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class WrappedKey:
    """A data key wrapped by an organisation key, and which version of that key wrapped it."""

    ciphertext: bytes
    key_version: int


@runtime_checkable
class KeyProvider(Protocol):
    def wrap_data_key(self, org_id: uuid.UUID, data_key: bytes) -> WrappedKey:
        """Wrap a 32-byte contact data key under the organisation's active key version.

        The implementation binds the call to the organisation (the managed KMS adapter sends the encryption context ``{"cv_org": <org id>}``, which the
        cloud roles' key policies require), so a key
        wrapped for one organisation never unwraps for another.
        """
        ...

    def unwrap_data_key(self, org_id: uuid.UUID, wrapped: WrappedKey) -> bytes:
        """Return the 32-byte data key, or raise if the organisation key is gone or the binding does not match."""
        ...

    def fingerprint_secret(self, org_id: uuid.UUID) -> bytes:
        """Return the organisation's independent fingerprint secret (at least 32 bytes).

        Never derived from another key and never rotated for the life of the organisation: stop matching depends on
        it. Callers cache it in memory for at most 15 minutes.
        """
        ...
