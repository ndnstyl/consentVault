"""Named exceptions. Every failure path in consentvault raises one of these."""


class ConsentVaultError(Exception):
    """Base class for every error consentvault raises on purpose.

    ``code`` is an optional stable code chosen where the error is raised (``no_anchor_sink``, ``http_503``): lowercase letters,
    digits and underscores. It is what a log, a terminal or an alarm shows beside the class (safelog.describe), never the message."""

    def __init__(self, *args, code: str | None = None) -> None:
        super().__init__(*args)
        if code is not None:
            self.code = code


class ConfigError(ConsentVaultError):
    """A required setting is missing or malformed."""


class DatabaseError(ConsentVaultError):
    """The database could not be reached or refused an operation."""


class DatabaseCredentialsError(DatabaseError):
    """The credentials that sign a database login token are missing, unreachable or unusable."""


class DatabaseSigningError(DatabaseError):
    """A database login token could not be signed."""


class DatabaseTlsError(DatabaseError):
    """The database's TLS certificate could not be verified, or the CA bundle to verify it is missing."""


class DatabaseAuthError(DatabaseError):
    """The database refused the login token."""


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
