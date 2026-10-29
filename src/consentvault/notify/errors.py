"""Named errors for the transactional email module."""

from consentvault.errors import ConsentVaultError


class NotifyError(ConsentVaultError):
    """Base class for every notify failure."""


class NotifyRefused(NotifyError):
    """A message was refused before any send: bad variable, unknown template, or unsafe content."""


class NotifyConfigError(NotifyError):
    """A sender is missing a setting or cannot be made safe (for example, no STARTTLS)."""


class SendFailed(NotifyError):
    """The provider did not accept the message. The text carries the exception type and the provider's code only,
    never the provider's message (it can quote the recipient's address)."""

    def __init__(self, provider: str, kind: str, code: int | str | None = None) -> None:
        self.provider, self.kind, self.code = provider, kind, code
        super().__init__(f"{provider} send failed: {kind}" + (f" (code {code})" if code is not None else ""))


class SendLogError(NotifyError):
    """A send log row could not be written."""
