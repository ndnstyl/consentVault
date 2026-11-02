"""Named errors of the suppression-sync layer. Every failure path raises one of these."""

from ..errors import ConsentVaultError


class SyncError(ConsentVaultError):
    """A sync operation could not be completed."""


class OutboxTransactionError(SyncError):
    """The outbox hook was called outside the transaction that records the event."""


class OutboxError(SyncError):
    """A push could not be queued; the capture transaction must roll back with it."""


class SystemExistsError(SyncError):
    """A connected system with that name already exists in the organisation."""


class SystemNotFoundError(SyncError):
    """No such connected system (or redrive, or credential binding) in the organisation."""


class EndpointNotHttpsError(SyncError):
    """A connected system endpoint is not an https address."""


class SystemValidationError(SyncError):
    """A connected system field is missing or malformed."""


class CredentialError(SyncError):
    """A system's signing credential is missing, malformed or cannot be opened."""


class RedriveInProgressError(SyncError):
    """A redrive for that system is still running."""


class ScopeRefusedError(SyncError):
    """The token holds none of the scopes the call needs."""


class StaleAttemptError(SyncError):
    """An attempt was finished after it was no longer the open one (its lease was taken over)."""


class TransportError(SyncError):
    """The delivery door itself failed (not the receiver): its credential, its address or its answer is wrong."""


class WorkerError(SyncError):
    """A worker run ended with failures it could not resolve; the report names them."""


class AlarmSinkError(SyncError):
    """An alarm could not be raised; the dead rows stay unalarmed and are reported again on the next run."""


class SignalValidationError(SyncError):
    """An inbound signal is missing a field or carries a malformed one; ``fields`` maps field to reason."""

    def __init__(self, message: str, fields: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.fields = fields or {}


class InvalidContactError(SyncError):
    """The contact point is not a valid phone number or email address."""


class NoSystemForCredentialError(SyncError):
    """The credential is bound to no connected system, so it cannot send signals."""
