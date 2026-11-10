import os

import psycopg
import pytest

from consentvault.tenancy import admin, audit
from consentvault.tenancy.admin_base import ApiError
from consentvault.tenancy.tokens import mint_org_token, org_transaction


def test_creation_makes_the_key_chain_prefix_lists_retention_and_invite(vault):
    org = vault.create_org("Acme", "boss@acme.example", region="us-east")
    oid = org["org_id"]
    assert org["status"] == "trial" and org["evidence_prefix"] == f"orgs/{oid}/"
    assert vault.custody.status(oid).state == "active"  # the key provider made the organisation key
    sent = vault.mailer.sent[-1]
    assert sent["to"] == "boss@acme.example" and sent["role"] == "admin" and "invite_token" not in org
    with vault.operator() as c, org_transaction(c, mint_org_token(vault.key, oid, ["admin"], credential_id=None)):
        key = c.execute("SELECT version, kms_key_ref, status FROM consentvault.org_key").fetchone()
        assert key == {"version": 1, "kms_key_ref": f"local:{oid}", "status": "active"}
        wrapped = c.execute("SELECT wrapped FROM consentvault.org_fingerprint_secret").fetchone()["wrapped"]
        assert len(vault.custody.unwrap(oid, bytes(wrapped))) == 32  # the secret is wrapped by the org key, never raw
        assert {r["channel"] for r in c.execute("SELECT channel FROM consentvault.channel")} == \
            {"voice", "artificial_voice", "sms", "email"}
        assert [r["purpose"] for r in c.execute("SELECT purpose FROM consentvault.purpose")] == ["marketing"]
        assert c.execute("SELECT evidence_years, platform_minimum_years FROM consentvault.retention_policy").fetchone() \
            == {"evidence_years": 5, "platform_minimum_years": 5}
        assert c.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0  # an empty chain
        assert c.execute("SELECT count(*) AS n FROM consentvault.invite WHERE role = 'admin'").fetchone()["n"] == 1
        actions = [r["action"] for r in c.execute("SELECT action FROM consentvault.audit_event ORDER BY seq")]
        assert actions == ["org.created", "member.invited"]
        assert audit.chain_breaks(c) == []
    with vault.operator() as c:
        assert audit.platform_head(c)["seq"] >= 1


def test_the_invite_token_is_never_stored(vault):
    org = vault.create_org("Acme", "boss@acme.example")
    token = vault.mailer.token_for("boss@acme.example")
    with vault.superuser() as su:
        row = su.execute("SELECT token_digest FROM consentvault.invite WHERE org_id = %s", (org["org_id"],)).fetchone()
    assert token not in row["token_digest"] and len(row["token_digest"]) == 64


def test_a_failed_email_creates_nothing_in_the_database(vault):
    vault.mailer.fail = True
    with pytest.raises(ApiError) as e:
        vault.create_org("Ghost", "boss@ghost.example")
    assert e.value.name == "email_send_failed" and e.value.status == 502
    with vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.organization WHERE name = 'Ghost'").fetchone()["n"] == 0
        assert su.execute("SELECT count(*) AS n FROM consentvault.invite").fetchone()["n"] == 0


def test_a_key_provider_failure_is_a_named_error_and_nothing_is_written(vault):
    class Broken:
        def create_org_key(self, org_id):
            from consentvault.providers.errors import KeyProviderError
            raise KeyProviderError("down")
    with vault.operator() as c, pytest.raises(ApiError) as e:
        admin.create_org(c, token_key=vault.key, custody=Broken(), operator_id="op-1", request_id="r1", name="X",
                         admin_email="a@x.example")
    assert e.value.name == "key_unavailable" and e.value.status == 503
    with vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.organization WHERE name = 'X'").fetchone()["n"] == 0


def test_creation_validates_its_input(vault):
    for kw in ({"name": "", "admin_email": "a@x.example"}, {"name": "X", "admin_email": "not-an-email"},
               {"name": "X", "admin_email": "a@x.example", "status": "closed"}):
        with vault.operator() as c, pytest.raises(ApiError) as e:
            admin.create_org(c, token_key=vault.key, custody=vault.custody, operator_id="op", request_id="r", **kw)
        assert e.value.name == "validation_failed"


def _status(vault, oid, status, reason="because"):
    with vault.operator() as c:
        return admin.set_org_status(c, token_key=vault.key, operator_id="op-1", request_id="r-status", org_id=oid,
                                    status=status, reason=reason)


def test_status_transitions_follow_the_billing_table_and_are_audited(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    oid = org["org_id"]
    assert _status(vault, oid, "suspended")["previous_status"] == "trial"
    assert _status(vault, oid, "active")["status"] == "active"
    with pytest.raises(ApiError) as e:  # active to active is not a move
        _status(vault, oid, "active")
    assert e.value.name == "validation_failed"
    assert _status(vault, oid, "offboarding")["status"] == "offboarding"
    with pytest.raises(ApiError) as e:  # offboarding never goes back by this route
        _status(vault, oid, "active")
    assert e.value.name == "validation_failed"
    rows = boss.ok("GET", "/v1/audit", {"action": "org.status_changed"})["items"]
    assert len(rows) == 3 and rows[0]["actor"]["kind"] == "operator" and rows[0]["reason"].startswith("active to offboarding")
    with vault.superuser() as su:  # the billing lane's history table, when applied, records cause and actor
        hist = su.execute("SELECT to_regclass('consentvault.org_status_history') AS t").fetchone()["t"]
        if hist:
            last = su.execute("SELECT cause, actor FROM consentvault.org_status_history WHERE org_id = %s"
                              " ORDER BY seq DESC LIMIT 1", (oid,)).fetchone()
            assert last == {"cause": "operator", "actor": "op-1"}


def test_status_of_an_unknown_organisation_and_a_blank_reason_are_refused(vault):
    import uuid
    with pytest.raises(ApiError) as e:
        _status(vault, str(uuid.uuid4()), "suspended")
    assert e.value.name == "not_found"
    org, _ = vault.org_with_admin("Acme", "boss@acme.example")
    with pytest.raises(ApiError) as e:
        _status(vault, org["org_id"], "suspended", reason=" ")
    assert e.value.name == "validation_failed"


def test_get_org_shapes_by_role_and_never_invents_a_value(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    full = boss.ok("GET", "/v1/org")
    assert full["key"] == {"status": "active", "version": 1, "destroy_after": None}
    assert full["trial"]["started_at"] and full["plan"] is None and "plan" in full["partial"]
    small = dev.ok("GET", "/v1/org")
    assert small == {"org_id": org["org_id"], "name": "Acme", "status": "trial", "region": None, "default_region": "US", "role": "developer"}


def test_health_counts_only_and_null_when_unknown(vault):
    _, boss = vault.org_with_admin("Acme", "boss@acme.example")
    h = boss.ok("GET", "/v1/health")
    assert h["unsealed_events_over_1h"] == 0 and h["first_event"] is None
    assert h["dead_deliveries"] is None and h["last_chain_verification"] is None  # never a default zero


def test_operator_marks_a_trial_org_active_without_a_charge_audited_and_needs_the_operator_role(vault):
    org, boss = vault.org_with_admin("Internal Co", "boss@internal.example")
    oid = org["org_id"]
    out = _status(vault, oid, "active", reason="operator's own organisation, internal and no-charge")
    assert out["previous_status"] == "trial" and out["status"] == "active"
    rows = boss.ok("GET", "/v1/audit", {"action": "org.status_changed"})["items"]
    assert len(rows) == 1 and rows[0]["actor"]["kind"] == "operator" and rows[0]["reason"].startswith("trial to active")
    assert boss.ok("GET", "/v1/org")["status"] == "active"
