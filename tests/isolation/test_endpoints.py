"""Every tenant endpoint run with organisation B's credentials against organisation A's records.

For each endpoint: B never sees A's rows, and what B gets for a contact only A holds is the same answer, in shape and
roughly in time, as for a contact nobody holds, so an answer never hints that another organisation exists.
"""

import statistics
import time

import pytest

from consentvault import api
from consentvault.tenancy.pipeline import verify_receipt

from .cloud_harness import Cloud, approve_policy, policy_rules, without

X = "+15555550177"  # held by organisation A only
U = "+15555550188"  # held by nobody


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def _err(body: dict) -> dict:
    return without(body, "request_id")


# token endpoint ----------------------------------------------------------------------------------------------------
def test_token_carries_only_the_credentials_own_organisation(cloud):
    for co in (cloud.a, cloud.b):
        claims = cloud.access.verify(cloud.token(co, "capture"))
        assert claims.org_id == co.org.org_id and claims.scopes == ("capture",)


def test_an_assertion_naming_the_other_orgs_client_is_refused_like_an_unknown_client(cloud):
    a_cap, b_cap = cloud.a.clients["capture"], cloud.b.clients["capture"]
    forged = cloud.token_form(a_cap)  # A's key, but claiming to be B's client
    from consentvault.tenancy.oauth import make_client_assertion
    forged["client_assertion"] = make_client_assertion(a_cap.key, alg="ES256", client_id=b_cap.credential_id,
                                                       audience="https://api.consentvault.test/v1/oauth/token")
    s1, b1 = cloud.call("/v1/oauth/token", form=forged)
    unknown = cloud.token_form(a_cap)
    unknown["client_assertion"] = make_client_assertion(a_cap.key, alg="ES256",
                                                        client_id="7e1c8a1e-0000-4000-8000-000000000001",
                                                        audience="https://api.consentvault.test/v1/oauth/token")
    s2, b2 = cloud.call("/v1/oauth/token", form=unknown)
    assert s1 == s2 == 401 and _err(b1) == _err(b2) == {"error": "invalid_client",
                                                        "detail": "client authentication failed"}


def test_token_refusals_are_named(cloud):
    cap = cloud.a.clients["capture"]
    form = cloud.token_form(cap, jti="replayed-jti-0001")
    assert cloud.call("/v1/oauth/token", form=form)[0] == 200
    s, b = cloud.call("/v1/oauth/token", form=form)
    assert (s, b["error"]) == (401, "invalid_client")  # replay
    s, b = cloud.call("/v1/oauth/token", form=cloud.token_form(cap, now=time.time() - 3600))
    assert (s, b["error"]) == (401, "invalid_client")  # expired
    s, b = cloud.call("/v1/oauth/token", form=cloud.token_form(cap, lifetime=3600))
    assert (s, b["error"]) == (401, "invalid_client")  # longer than five minutes
    for scope in ("admin", "gate_read", "operator"):
        s, b = cloud.call("/v1/oauth/token", form=cloud.token_form(cap, scope=scope))
        assert (s, b["error"]) == (400, "invalid_request")
    s, b = cloud.call("/v1/oauth/token", form={"grant_type": "password"})
    assert (s, b["error"]) == (400, "invalid_request")


def test_an_access_token_signed_by_another_key_is_unauthenticated(cloud):
    from consentvault.tenancy.oauth import AccessTokenSigner
    other = AccessTokenSigner.generate(key_id="at-test", issuer="https://api.consentvault.test")
    forged = other.issue({"iss": "https://api.consentvault.test", "org_id": str(cloud.a.org.org_id),
                          "credential_id": cloud.a.clients["proof_read"].credential_id, "scope": "proof_read",
                          "jti": "x", "exp": int(time.time()) + 200})
    s, b = cloud.proof(cloud.a, X, token=forged)
    assert (s, b["error"]) == (401, "unauthenticated")


def test_a_closed_organisation_gets_no_token_and_a_suspended_one_still_does(cloud):
    with cloud.t.superuser() as su:
        su.execute("UPDATE consentvault.organization SET status = 'suspended' WHERE org_id = %s", (cloud.b.org.org_id,))
    assert cloud.grant(cloud.b, X)[0] == 201  # capture never stops for payment
    assert cloud.gate(cloud.b, X)[0] == 200
    with cloud.t.superuser() as su:
        su.execute("UPDATE consentvault.organization SET status = 'closed' WHERE org_id = %s", (cloud.b.org.org_id,))
    s, b = cloud.call("/v1/oauth/token", form=cloud.token_form(cloud.b.clients["capture"]))
    assert (s, b["error"]) == (403, "org_not_active")


# capture -----------------------------------------------------------------------------------------------------------
def _last_post(cloud, org):
    from .cloud_harness import raw_posts
    return raw_posts(cloud.t, org.org_id)[-1]


def _facts_of_last(cloud, org):
    from .cloud_harness import facts_of
    return facts_of(cloud.t, _last_post(cloud, org))


def test_capture_answers_a_receipt_with_the_fingerprint_and_the_receipt_verifies(cloud):
    from consentvault.rawpost import verify_post_receipt

    s, b = cloud.grant(cloud.a, X)
    assert s == 201 and {"stored", "post_id", "received_at", "body_sha256", "body_bytes", "unusual_size", "receipt"} <= set(b)
    assert b["stored"] is True and len(b["body_sha256"]) == 64 and b["unusual_size"] is False
    r = b["receipt"]
    assert r["org_id"] == str(cloud.a.org.org_id) and r["post_id"] == b["post_id"] and r["seq"] >= 1
    assert r["body_sha256"] == b["body_sha256"]
    assert verify_post_receipt(r, cloud.receipts.public_key, "rcpt-test")
    assert not verify_post_receipt({**r, "seq": r["seq"] + 1}, cloud.receipts.public_key, "rcpt-test")
    assert not verify_post_receipt({**r, "body_sha256": "0" * 64}, cloud.receipts.public_key, "rcpt-test")


def test_capture_stores_another_orgs_source_brand_and_wording_exactly_like_ones_that_do_not_exist(cloud):
    import uuid
    a, b = cloud.a, cloud.b
    cases = [
        ({"source_id": str(b.org.source_id)}, {"source_id": str(uuid.uuid4())}, "source_not_allowed"),
        ({"brand_ids": [str(b.org.brand_id)]}, {"brand_ids": [str(uuid.uuid4())]}, "brand_not_allowed"),
        ({"disclosure_sha256": b.wording}, {"disclosure_sha256": "ab" * 32}, "UnknownDisclosureError"),
    ]
    for theirs, nobodys, name in cases:
        s1, r1 = cloud.grant(a, X, **theirs)
        f1 = _facts_of_last(cloud, a.org)
        s2, r2 = cloud.grant(a, X, **nobodys)
        f2 = _facts_of_last(cloud, a.org)
        # the sender is told the same thing either way (stored); the operator's record names the same reason either way
        assert s1 == s2 == 201 and r1["stored"] is r2["stored"] is True
        assert f1["event_not_derived"] == f2["event_not_derived"] == name
    s, r = cloud.call("/v1/events", {"contact": X, "event_type": "revoke", "channels": ["sms"],
                                     "purposes": ["marketing"], "org_id": str(b.org.org_id)},
                      token=cloud.token(a, "capture"))
    assert s == 201 and r["receipt"]["org_id"] == str(a.org.org_id)  # the org never comes from the body
    with cloud.t.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.raw_post WHERE org_id = %s", (b.org.org_id,)).fetchone()["n"] == 0


def test_only_capture_verified_may_claim_a_verified_contact(cloud):
    s, r = cloud.grant(cloud.a, X, contact_verification="otp")
    assert s == 201 and r["stored"] is True
    assert _facts_of_last(cloud, cloud.a.org)["event_not_derived"] == "role_not_allowed"
    s, r = cloud.grant(cloud.a, X, contact_verification="otp", token=cloud.token(cloud.a, "capture_verified"))
    assert s == 201 and r["event_id"]
    with cloud.t.superuser() as su:
        assert su.execute("SELECT contact_verification FROM consentvault.event WHERE event_id = %s", (r["event_id"],)
                          ).fetchone()["contact_verification"] == "otp"


def test_an_unknown_purpose_or_channel_is_stored_and_the_reason_is_a_fact(cloud):
    s, r = cloud.grant(cloud.a, X, purposes=["surveys"])
    assert s == 201 and r["stored"] is True and "event_id" not in r
    assert _facts_of_last(cloud, cloud.a.org)["event_not_derived"] == "UnknownPurposeError"
    s, r = cloud.grant(cloud.a, X, channels=["fax"])
    assert s == 201 and r["stored"] is True and "event_id" not in r
    assert _facts_of_last(cloud, cloud.a.org)["event_not_derived"] == "invalid_channel"


def test_scopes_are_held_to_their_endpoints_and_a_capture_with_the_wrong_scope_is_stored_on_the_platform_intake(cloud):
    cap, gate, proof = (cloud.token(cloud.a, w) for w in ("capture", "gate_read", "proof_read"))
    assert cloud.gate(cloud.a, X, token=cap)[1]["error"] == "role_not_allowed"
    assert cloud.proof(cloud.a, X, token=gate)[1]["error"] == "role_not_allowed"
    s, r = cloud.grant(cloud.a, X, token=proof)
    assert s == 201 and r["stored"] is True and r["receipt"]["org_id"] == str(cloud.t.home) and "event_id" not in r
    from .cloud_harness import facts_of, raw_posts
    assert facts_of(cloud.t, raw_posts(cloud.t, cloud.t.home)[-1])["credential"]["reason"] == "ApiError"


# gate -----------------------------------------------------------------------------------------------------------------
def test_gate_answers_the_facts_and_history_never_a_verdict_or_a_legal_conclusion(cloud):
    assert cloud.grant(cloud.a, X)[0] == 201
    s, g = cloud.gate(cloud.a, X)
    assert s == 200 and g["status"] == "records_found" and [x["event_type"] for x in g["history"]] == ["grant"]
    assert g["notice"].endswith("does not decide.")
    assert set(g) == {"status", "history", "stops", "lifts", "decision_id", "evaluated_at", "notice"}
    assert not any(k in g for k in ("allowed", "permitted", "lawful", "compliant", "policy_action", "policy_version",
                                    "reasons", "evidence_status"))


def test_gate_from_b_on_a_contact_only_a_holds_matches_a_contact_nobody_holds(cloud):
    assert cloud.grant(cloud.a, X)[0] == 201
    tok = cloud.token(cloud.b, "gate_read")
    s1, g1 = cloud.gate(cloud.b, X, token=tok)
    s2, g2 = cloud.gate(cloud.b, U, token=tok)
    assert s1 == s2 == 200
    assert without(g1, "decision_id", "evaluated_at") == without(g2, "decision_id", "evaluated_at")
    assert g1["status"] == "no_record_found" and g1["history"] == [] and g1["stops"] == [] and g1["lifts"] == []


def test_gate_timing_does_not_reveal_another_orgs_contact(cloud):
    for i in range(3):
        cloud.grant(cloud.a, X)
    tok = cloud.token(cloud.b, "gate_read")
    cloud.gate(cloud.b, U, token=tok)  # warm

    def timed(contact):
        t0 = time.perf_counter()
        cloud.gate(cloud.b, contact, token=tok)
        return time.perf_counter() - t0

    held = statistics.median(timed(X) for _ in range(15))
    nobody = statistics.median(timed(U) for _ in range(15))
    assert abs(held - nobody) < max(0.02, 0.5 * min(held, nobody)), (held, nobody)


def test_gate_batch_answers_in_order_and_records_each_item(cloud):
    assert cloud.grant(cloud.a, X)[0] == 201
    items = [{"contact": X, "channel": "sms", "purpose": "marketing"},
             {"contact": "not a phone", "channel": "sms", "purpose": "marketing"},
             {"contact": U, "channel": "sms", "purpose": "marketing"}]
    s, r = cloud.call("/v1/permission:batch", {"items": items}, token=cloud.token(cloud.a, "gate_read"))
    assert s == 200 and [i.get("status", i.get("error")) for i in r["items"]] == \
        ["records_found", "invalid_contact", "no_record_found"]
    with cloud.t.superuser() as su:
        n = su.execute("SELECT count(*) AS n FROM consentvault.gate_decision WHERE batch_id = %s",
                       (r["batch_id"],)).fetchone()["n"]
        orgs = {x["org_id"] for x in su.execute("SELECT DISTINCT org_id FROM consentvault.gate_decision")}
    assert n == 2 and orgs == {cloud.a.org.org_id}


def test_a_stored_policy_changes_nothing_in_the_answer_and_a_stop_is_a_stop_line(cloud):
    approve_policy(cloud.t, cloud.b.org, policy_rules(narrowing=[
        {"kind": "require_verified_contact", "channels": ["sms"],
         "rule_reference_id": "00000000-0000-0000-0000-000000000000"}]))
    assert cloud.grant(cloud.b, X)[0] == 201
    s, g = cloud.gate(cloud.b, X)
    assert g["status"] == "records_found" and g["stops"] == [] and "policy_action" not in g
    stop = {"contact": X, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword"}
    assert cloud.call("/v1/events", stop, token=cloud.token(cloud.b, "capture"))[0] == 201
    s, g = cloud.gate(cloud.b, X)
    assert [x["event_type"] for x in g["history"]] == ["grant", "revoke"]
    assert [x["event_type"] for x in g["stops"]] == ["revoke"] and g["stops"][0]["lifted_by_post_ids"] == []


# proof ----------------------------------------------------------------------------------------------------------------
def test_proof_shows_a_its_own_record_and_b_nothing(cloud):
    assert cloud.grant(cloud.a, X)[0] == 201
    cloud.gate(cloud.a, X)
    s, p = cloud.proof(cloud.a, X)
    assert s == 200 and p["found"] is True and p["partial"] == []
    assert p["doc_check_results"] == []  # stored results are readable now; this record was never checked
    assert p["timeline"]["items"][0]["event_type"] == "grant"
    assert p["gate_decisions"]["items"][0]["evidence_status"] == "records_found"
    assert p["permissions"][0]["status"] == "records_found" and "policy_action" not in p["permissions"][0]
    assert X not in str(p)  # never a contact point
    tok = cloud.token(cloud.b, "proof_read")
    s1, p1 = cloud.proof(cloud.b, X, token=tok)
    s2, p2 = cloud.proof(cloud.b, U, token=tok)
    assert s1 == s2 == 200 and without(p1, "evaluated_at") == without(p2, "evaluated_at")
    assert set(p1) == {"found", "evaluated_at", "notice", "permissions"} and p1["permissions"] == []


def test_a_proof_cursor_does_not_cross_contacts_or_organisations(cloud):
    for _ in range(3):
        assert cloud.grant(cloud.a, X)[0] == 201
    s, p = cloud.proof(cloud.a, X, page={"section": "timeline", "limit": 1})
    cur = p["timeline"]["next_cursor"]
    assert s == 200 and len(p["timeline"]["items"]) == 1 and cur
    s, p2 = cloud.proof(cloud.a, X, page={"section": "timeline", "limit": 1, "cursor": cur})
    assert s == 200 and p2["timeline"]["items"][0]["seq"] > p["timeline"]["items"][0]["seq"]
    for co, contact in ((cloud.a, U), (cloud.b, X)):
        s, r = cloud.proof(co, contact, page={"section": "timeline", "limit": 1, "cursor": cur})
        assert (s, r.get("error", r.get("found"))) in ((400, "invalid_cursor"), (200, False))


# client-supplied evidence ----------------------------------------------------------------------------------------------
def test_ebr_and_dnc_scrub_records_land_in_the_callers_org_only(cloud):
    tok = cloud.token(cloud.b, "capture")
    s, r = cloud.call("/v1/ebr-records", {"contact": X, "relationship_type": "purchase", "started_on": "2026-01-02",
                                          "source": "crm-export", "evidence_refs": ["invoice 44"]}, token=tok)
    assert s == 201 and "ebr_id" in r
    s, r = cloud.call("/v1/dnc-scrubs", {"contact": X, "registry": "us_national", "scrubbed_at": "2026-10-01T00:00:00Z",
                                         "result": "not_listed", "provider": "scrubco"}, token=tok)
    assert s == 201 and "scrub_id" in r
    s, r = cloud.call("/v1/dnc-scrubs", {"contact": X, "registry": "us_national", "scrubbed_at": "2026-10-01T00:00:00Z",
                                         "result": "qualifies", "provider": "scrubco"}, token=tok)
    assert (s, r["error"]) == (422, "validation_failed")
    with cloud.t.superuser() as su:
        for table in ("ebr_record", "dnc_scrub_result"):
            rows = su.execute(f"SELECT org_id, recorded_by FROM consentvault.{table}").fetchall()
            assert {x["org_id"] for x in rows} == {cloud.b.org.org_id}
        assert su.execute("SELECT evidence_refs_ct FROM consentvault.ebr_record").fetchone()["evidence_refs_ct"]


def test_every_endpoint_error_carries_the_request_id(cloud):
    s, r = cloud.call("/v1/proof", {"contact": X}, headers={"X-Request-Id": "req-123"})
    assert (s, r) == (401, {"error": "unauthenticated", "detail": r["detail"], "request_id": "req-123"})
    s, r = cloud.call("/v1/nowhere", {})
    assert (s, r["error"]) == (404, "not_found")


# startup ----------------------------------------------------------------------------------------------------------------
def test_the_api_refuses_to_serve_a_single_mode_vault(app_dsn):
    with pytest.raises(api.StartupRefusedError, match="single mode"):
        api.startup_check(app_dsn)


def test_the_api_refuses_to_serve_when_an_owner_rights_function_lost_its_owner(cloud):
    api.startup_check(cloud.t.app_dsn)
    with cloud.t.superuser() as su:
        su.execute("ALTER FUNCTION consentvault.home_org() OWNER TO postgres")
    with pytest.raises(api.StartupRefusedError, match="home_org"):
        api.startup_check(cloud.t.app_dsn)
    with cloud.t.superuser() as su:
        su.execute("ALTER FUNCTION consentvault.home_org() OWNER TO cv_test_owner")
        su.execute("ALTER TABLE consentvault.gate_decision OWNER TO postgres")
    with pytest.raises(api.StartupRefusedError, match="gate_decision"):
        api.startup_check(cloud.t.app_dsn)


@pytest.mark.parametrize("by", [660.0, -660.0], ids=["ahead", "behind"])
def test_an_assertion_stamped_eleven_minutes_off_the_database_clock_is_refused(cloud, by):
    cap = cloud.a.clients["capture"]
    s, b = cloud.call("/v1/oauth/token", form=cloud.token_form(cap, now=time.time() + by))
    assert (s, b["error"]) == (401, "invalid_client")


@pytest.mark.parametrize("by", [660.0, -660.0], ids=["ahead", "behind"])
def test_the_token_endpoint_judges_an_assertion_on_the_database_clock_whatever_the_host_clock(cloud, monkeypatch, by):
    cap = cloud.a.clients["capture"]
    form = cloud.token_form(cap)                      # stamped with the true time
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + by)   # this host's clock, 11 minutes out
    s, b = cloud.call("/v1/oauth/token", form=form)
    assert s == 200, b
