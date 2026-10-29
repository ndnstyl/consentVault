"""Second-wave adversarial review, ported: a Stripe payment never lifts an operator's suspension."""

from .fakes import event
from .helpers import link, routes_for, send, set_status, status_of, subscribed


def _reason(tenancy, org):
    with tenancy.superuser() as su:
        return su.execute("SELECT suspension_reason FROM consentvault.organization WHERE org_id = %s",
                          (org.org_id,)).fetchone()["suspension_reason"]


def test_invoice_paid_lifts_an_operator_suspension(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub)
    set_status(tenancy, org, "suspended")   # operator suspends (abuse, legal hold, ...)
    assert _reason(tenancy, org) == "operator"
    inv = stripe.add_invoice(cus, sub, "paid")  # org admin pays any open invoice in the Stripe portal
    _, body = send(routes_for(tenancy, stripe), event("invoice.paid", inv, "invoice"))
    assert status_of(tenancy, org) == "suspended", "operator suspension was lifted by a Stripe payment"
    set_status(tenancy, org, "active")  # an operator action lifts it
    assert _reason(tenancy, org) is None


def test_a_suspension_for_a_canceled_subscription_is_lifted_by_a_paid_invoice(tenancy, stripe):
    org = tenancy.a
    cus, sub = subscribed(stripe, org)
    link(tenancy, org, cus, sub)
    with tenancy.superuser() as su:
        su.execute("SELECT consentvault.billing_apply_status(%s, 'suspended', 'subscription_deleted', 'evt_1')",
                   (org.org_id,))
    assert (status_of(tenancy, org), _reason(tenancy, org)) == ("suspended", "subscription_canceled")
    inv = stripe.add_invoice(cus, sub, "paid")
    send(routes_for(tenancy, stripe), event("invoice.paid", inv, "invoice"))
    assert (status_of(tenancy, org), _reason(tenancy, org)) == ("active", None)


def test_an_operator_suspension_over_a_billing_one_takes_ownership(tenancy, stripe):
    org = tenancy.a
    with tenancy.superuser() as su:
        su.execute("SELECT consentvault.billing_apply_status(%s, 'suspended', 'subscription_deleted', 'evt_2')",
                   (org.org_id,))
        su.execute("UPDATE consentvault.organization SET status = 'suspended' WHERE org_id = %s", (org.org_id,))
        assert su.execute("SELECT consentvault.billing_apply_status(%s, 'active', 'invoice_paid', 'evt_3') AS r",
                          (org.org_id,)).fetchone()["r"] == "refused_operator_suspension"
        # the reason cannot be written by hand to unlock the webhook path: the trigger owns it
        su.execute("UPDATE consentvault.organization SET suspension_reason = 'subscription_canceled' WHERE org_id = %s",
                   (org.org_id,))
    assert _reason(tenancy, org) == "operator"
