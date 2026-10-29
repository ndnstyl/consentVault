"""Named errors of the tenancy layer. Every failure path raises one of these."""

from ..errors import ConsentVaultError


class TenancyError(ConsentVaultError):
    """A tenancy operation could not be completed."""


class TenantTokenError(TenancyError):
    """A tenant token could not be minted, or the database refused it."""


class TenantRequiredError(TenancyError):
    """The operation needs a tenant and none is entered."""


class KeyProviderError(TenancyError):
    """The key provider could not wrap, unwrap or supply a secret."""


class FieldCryptoError(TenancyError):
    """A field could not be encrypted, or its ciphertext is malformed."""


class FieldDecryptError(FieldCryptoError):
    """A ciphertext failed authentication: wrong key, or bound to another organisation, record or column."""


class ContactKeyMissingError(TenancyError):
    """The contact's data key is gone (erased) or was never written."""


class ReplayError(TenancyError):
    """A nonce or token id was presented a second time."""
