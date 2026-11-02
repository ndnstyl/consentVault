"""Wave 2 hardening, item (b): an operator may re-suspend a suspended organisation; the reason becomes operator."""

from consentvault.tenancy import admin


def _status(vault, oid, status, reason="because"):
    with vault.operator() as c:
        return admin.set_org_status(c, token_key=vault.key, operator_id="op-1", request_id="r-status", org_id=oid,
                                    status=status, reason=reason)


def _reason(vault, oid):
    with vault.superuser() as su:
        return su.execute("SELECT status, suspension_reason FROM consentvault.organization WHERE org_id = %s",
                          (oid,)).fetchone()


def test_an_operator_may_resuspend_a_suspended_org_and_the_reason_becomes_operator(vault):
    org, _ = vault.org_with_admin("Acme", "boss@acme.example")
    oid = org["org_id"]
    _status(vault, oid, "suspended")
    with vault.superuser() as su:  # a subscription-ended suspension: a paid invoice could lift it
        su.execute("SELECT set_config('consentvault.status_cause', 'subscription_deleted', false)")
        su.execute("UPDATE consentvault.organization SET status = 'active' WHERE org_id = %s", (oid,))
        su.execute("UPDATE consentvault.organization SET status = 'suspended' WHERE org_id = %s", (oid,))
        su.execute("UPDATE consentvault.organization SET suspension_reason = 'subscription_canceled' WHERE org_id = %s", (oid,))
    assert _reason(vault, oid)["suspension_reason"] == "subscription_canceled"
    out = _status(vault, oid, "suspended", reason="abuse report")
    assert (out["status"], out["previous_status"]) == ("suspended", "suspended")
    assert _reason(vault, oid) == {"status": "suspended", "suspension_reason": "operator"}
