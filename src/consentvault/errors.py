"""Named exceptions. Every failure path in consentvault raises one of these."""


class ConsentVaultError(Exception):
    """Base class for every error consentvault raises on purpose."""


class ConfigError(ConsentVaultError):
    """A required setting is missing or malformed."""


class DatabaseError(ConsentVaultError):
    """The database could not be reached or refused an operation."""


class MigrationError(ConsentVaultError):
    """A migration could not be applied."""


class MigrationDriftError(MigrationError):
    """An applied migration file changed, or an applied file is missing."""


class NormalizationError(ConsentVaultError):
    """A phone number or email could not be normalized."""


class ConsentRefusedError(ConsentVaultError):
    """The request is not a valid grant of consent."""


class UncheckedConsentError(ConsentRefusedError):
    """The consent box was not checked."""


class EmptyConsentError(ConsentRefusedError):
    """The grant names no channel or no purpose."""


class UnknownDisclosureError(ConsentVaultError):
    """A disclosure hash is not held by the vault."""


class InvalidEventError(ConsentVaultError):
    """An event field has a value outside the allowed set."""


class LedgerError(ConsentVaultError):
    """The ledger could not record an event."""


class ChainError(ConsentVaultError):
    """The hash chain failed verification."""


class GrantScopeError(InvalidEventError):
    """A grant names a channel or purpose its disclosure does not cover."""


class ClockSkewError(InvalidEventError):
    """captured_at is later than the vault's receipt time plus the allowed skew."""


class UnknownPurposeError(InvalidEventError):
    """A purpose is malformed or is not on the configured purpose list."""


class AnchorError(ConsentVaultError):
    """The chain head could not be anchored to the external sink."""


class ReleaseFailedError(ConsentVaultError):
    """A grant was recorded but its release decision could not be written."""
