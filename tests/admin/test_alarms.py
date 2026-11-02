"""Open alarms for customers on GET /v1/health: [{name, since, count|null, next_action}], filtered by role (admin.md, "which alarms
a customer sees"). No acknowledge action exists; each alarm leaves when its cause is fixed."""

import json
import uuid

from consentvault.ledger import record_tenant_event
from consentvault.tenancy.crypto import TenantCrypto
from consentvault.tenancy.tokens import mint_org_token, org_transaction


PHONE = "+15555550177"


def org_alarm(vault, org_id, kind, detail=None, cleared=False):
    with vault.superuser() as su:
        su.execute("INSERT INTO consentvault.org_alarm (org_id, kind, detail, cleared_at) VALUES (%s, %s, %s, %s)",
                   (org_id, kind, json.dumps(detail or {}), "2026-01-01T00:00:00Z" if cleared else None))


def operator_alarm(vault, org_id, name, acknowledged=False):
    with vault.superuser() as su:
        su.execute("INSERT INTO consentvault.operator_alarm (org_id, name, error_class, acknowledged_at, acknowledged_by)"
                   " VALUES (%s, %s, 'X', %s, %s)", (org_id, name, "2026-01-01T00:00:00Z" if acknowledged else None,
                                                    "operator" if acknowledged else None))


_CRYPTO: dict = {}


def _provider(org_id):
    from isolation.harness import FakeKeyProvider
    p = FakeKeyProvider()
    p.add_org(uuid.UUID(str(org_id)))
    return p


def stop_event(vault, org_id, recorded_by: str, phone: str, event_type="suppress"):
    purposes = ["*"] if event_type == "suppress" else ["marketing"]
    """One event on the organization's chain, written the way erasure and restore write theirs."""
    crypto = _CRYPTO.setdefault(str(org_id), TenantCrypto(_provider(org_id)))
    token = mint_org_token(vault.key, org_id, ["capture", "gate_read"], credential_id=None)
    with vault.appconn() as c, org_transaction(c, token):
        extra = {}
        if event_type == "grant":
            from consentvault import disclosure as disc
            extra["disclosure_sha256"] = disc.register(c, "Alarm Co may text you. Reply STOP to end.", "alarm-form", "en", ["sms"], ["marketing"])
        record_tenant_event(c, crypto, contact=phone, event_type=event_type, channels=["sms"], purposes=purposes, method="written",
                            origin="consumer", source="erasure", recorded_by=recorded_by,
                            **extra)


def names(h):
    return [a["name"] for a in h["alarms"]]


def test_the_shape_roles_and_ordering_of_the_alarm_list(vault):
    org, boss = vault.org_with_admin("Alarm Co", "boss@alarm-co.example")
    other, other_boss = vault.org_with_admin("Quiet Co", "boss@quiet-co.example")
    viewer = vault.add_member(boss, "view@alarm-co.example", "compliance_viewer")
    dev = vault.add_member(boss, "dev@alarm-co.example", "developer")
    assert boss.ok("GET", "/v1/health")["alarms"] == []
    org_alarm(vault, org["org_id"], "reveal_volume", {"member_id": None, "count": 5200, "window": "24h"})
    org_alarm(vault, org["org_id"], "sending_account_failing", {"account_id": "a1", "channel": "sms"})
    org_alarm(vault, org["org_id"], "link_host_failing", cleared=True)
    for who in (boss, viewer):
        alarms = who.ok("GET", "/v1/health")["alarms"]
        assert [a["name"] for a in alarms] == ["sending_account_failing", "reveal_volume"]
        assert set(alarms[0]) == {"name", "since", "count", "next_action"} and alarms[0]["since"].endswith("Z")
        assert alarms[1]["count"] == 5200 and alarms[0]["count"] is None
        assert all(len(a["next_action"]) > 20 for a in alarms)
    assert dev.ok("GET", "/v1/health")["alarms"] == [], "a developer's list is empty (alarms can name records and people)"
    assert other_boss.ok("GET", "/v1/health")["alarms"] == [], "another organization's alarms never cross"


def test_unconfirmed_stops_after_a_restore_go_to_admins_and_viewers_with_a_count_and_a_since(vault):
    org, boss = vault.org_with_admin("Restore Co", "boss@restore-co.example")
    viewer = vault.add_member(boss, "view@restore-co.example", "compliance_viewer")
    dev = vault.add_member(boss, "dev@restore-co.example", "developer")
    eid = str(uuid.uuid4())
    # two stops a restore put back unconfirmed; a third whose erasure the operator then confirmed; a fourth the person lifted
    stop_event(vault, org["org_id"], f"erasure-unconfirmed:{eid}:3", "+15555550101")
    stop_event(vault, org["org_id"], f"erasure-unconfirmed:{eid}:4", "+15555550102")
    stop_event(vault, org["org_id"], f"erasure-unconfirmed:{eid}:5", "+15555550103")
    stop_event(vault, org["org_id"], f"erasure:{eid}:5", "+15555550103")
    for who in (boss, viewer):
        got = [a for a in who.ok("GET", "/v1/health")["alarms"] if a["name"] == "restore.stops_unconfirmed"]
        assert len(got) == 1 and got[0]["count"] == 2 and got[0]["since"].endswith("Z")
        assert "Review them on the evidence lookup page" in got[0]["next_action"]
    assert dev.ok("GET", "/v1/health")["alarms"] == []
    stop_event(vault, org["org_id"], f"erasure-unconfirmed:{eid}:6", "+15555550104")
    assert boss.ok("GET", "/v1/health")["alarms"][0]["count"] == 3
    stop_event(vault, org["org_id"], "grant-after", "+15555550104", event_type="grant")  # the person's own consent lifts it
    assert boss.ok("GET", "/v1/health")["alarms"][0]["count"] == 2
    for seq in (3, 4):
        stop_event(vault, org["org_id"], f"erasure:{eid}:{seq}", f"+1555555010{seq - 2}")  # the operator confirms the rest
    assert boss.ok("GET", "/v1/health")["alarms"] == [], "every stop settled: the alarm is gone"


def test_a_second_live_subscription_is_for_admins_only_and_clears_when_the_billing_side_clears_it(vault):
    org, boss = vault.org_with_admin("Billing Co", "boss@billing-co.example")
    viewer = vault.add_member(boss, "view@billing-co.example", "compliance_viewer")
    operator_alarm(vault, org["org_id"], "billing.second_live_subscription")
    got = [a for a in boss.ok("GET", "/v1/health")["alarms"] if a["name"] == "billing.second_live_subscription"]
    assert len(got) == 1 and got[0]["count"] is None
    assert got[0]["next_action"] == "Your organization has two live subscriptions. Cancel the extra one in the billing portal (Manage billing on Stripe)."
    assert viewer.ok("GET", "/v1/health")["alarms"] == []
    with vault.superuser() as su:  # what the billing webhook does when Stripe shows one live subscription again
        su.execute("UPDATE consentvault.operator_alarm SET acknowledged_at = now(), acknowledged_by = 'stripe' WHERE org_id = %s",
                   (org["org_id"],))
    assert boss.ok("GET", "/v1/health")["alarms"] == []


def test_no_customer_role_ever_sees_a_usage_alarm_and_nothing_acknowledges(vault):
    org, boss = vault.org_with_admin("Usage Co", "boss@usage-co.example")
    viewer = vault.add_member(boss, "view@usage-co.example", "compliance_viewer")
    for n in ("usage_day_abandoned", "usage_send_unconfirmed", "usage_report_failed"):
        operator_alarm(vault, org["org_id"], n)
    for who in (boss, viewer):
        body = json.dumps(who.ok("GET", "/v1/health"))
        assert "usage_" not in body and who.ok("GET", "/v1/health")["alarms"] == []
    for path in ("/v1/alarms/x:acknowledge", "/v1/health/alarms/x/acknowledge", "/v1/alarms/x/acknowledge"):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            r = boss.call(method, path, body={})
            assert r.status in (404, 403), (method, path, r.status)
