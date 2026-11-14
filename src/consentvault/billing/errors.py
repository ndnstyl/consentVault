"""Named errors of the billing layer. Every failure path raises one of these."""

from ..errors import ConsentVaultError


class BillingError(ConsentVaultError):
    """A billing operation could not be completed."""


class WebhookSignatureError(BillingError):
    """The Stripe-Signature header is missing, malformed, stale, or does not match the body."""


class WebhookPayloadError(BillingError):
    """The webhook body is not a Stripe event the vault can read."""


class StripeUnavailableError(BillingError):
    """Stripe did not answer (network fault, timeout, 429 or 5xx). Nothing was changed; the caller may retry."""


class StripeRejectedError(BillingError):
    """Stripe answered and refused the request (4xx). Retrying the same request will not help."""


class PlanCatalogError(BillingError):
    """A Stripe Price that sells a plan is missing the metadata the vault reads, or carries a malformed value. ``price_id`` and
    ``check_problem`` carry the same facts as fields, so an alarm names them without reading the error's text."""

    def __init__(self, message: str, *, price_id: str = "", problem: str = "") -> None:
        super().__init__(message)
        self.price_id, self.check_problem = price_id, problem


class PlanNotFoundError(BillingError):
    """No plan with that id is on sale."""


class NotSubscribedError(BillingError):
    """The organisation has no Stripe customer yet."""


class AlreadySubscribedError(BillingError):
    """The organisation already has a subscription that is in force."""


class OrgNotActiveError(BillingError):
    """The organisation's status refuses this action entirely."""


class RoleNotAllowedError(BillingError):
    """The caller's role may not call this endpoint."""


class GateCountUnavailableError(BillingError):
    """The gate-check count for a day could not be read; a count is never reported as zero instead."""


class UsageReportError(BillingError):
    """One or more usage reports to Stripe failed after every retry."""
