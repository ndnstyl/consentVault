"""Named errors for the providers layer. Every provider failure raises one of these; none is swallowed."""

from ..errors import ConsentVaultError


class ProviderError(ConsentVaultError):
    """Base class for every provider failure."""


class ProviderConfigError(ProviderError):
    """A provider was built with a missing or malformed setting."""


class ProviderTransportError(ProviderError):
    """A provider's backing service was unreachable or answered with a server error."""


# keys
class KeyProviderError(ProviderError):
    """A key operation failed."""


class KeyNotFoundError(KeyProviderError):
    """No key exists for this org."""


class KeyExistsError(KeyProviderError):
    """A key already exists for this org; creating over it is refused."""


class KeyPendingDestructionError(KeyProviderError):
    """The key is scheduled for destruction and cannot be used until the schedule is cancelled."""


class KeyDestroyedError(KeyProviderError):
    """The key has been destroyed; what it wrapped is unreadable."""


class DestructionWindowError(KeyProviderError):
    """A destruction was scheduled with a waiting window shorter than the 30-day floor."""


class UnwrapError(KeyProviderError):
    """A wrapped key could not be unwrapped (wrong key, corrupted or tampered ciphertext)."""


# evidence
class EvidenceStoreError(ProviderError):
    """An evidence store operation failed."""


class EvidenceExistsError(EvidenceStoreError):
    """An object already exists at this key; evidence is write-once and is never overwritten."""


class EvidenceNotFoundError(EvidenceStoreError):
    """No object exists at this key."""


class EvidenceIntegrityError(EvidenceStoreError):
    """The stored bytes do not match the digest recorded at write time."""


class RetentionError(EvidenceStoreError):
    """The retention on an object is missing, weaker than required, or not compliance mode."""


class InvalidEvidenceKeyError(EvidenceStoreError):
    """An org id or object key contains characters that could escape its prefix."""


# anchors
class AnchorSinkError(ProviderError):
    """An anchor record could not be published to its sink."""


# identity
class IdentityError(ProviderError):
    """A token was refused."""


class TokenMalformedError(IdentityError):
    """The token is not a well-formed signed JWT."""


class UnsupportedAlgorithmError(IdentityError):
    """The token's signing algorithm is not on the allow list (including alg none and HMAC)."""


class SigningKeyNotFoundError(IdentityError):
    """No key in the issuer's JWKS matches the token's key id."""


class SignatureInvalidError(IdentityError):
    """The signature does not verify against the issuer's key."""


class IssuerMismatchError(IdentityError):
    """The token's issuer is not the configured issuer."""


class AudienceMismatchError(IdentityError):
    """The token was not issued for this audience."""


class TokenExpiredError(IdentityError):
    """The token has expired, or is not yet valid."""


class MfaRequiredError(IdentityError):
    """The token does not show a multi-factor login in its amr claim."""


class EdgeKeyUnknownError(ProviderConfigError):
    """The portal edge signed with a key id this vault does not hold. The caller did nothing wrong: the deployment is out of
    step (a key rotated away or never added), so this is never an authentication failure."""
