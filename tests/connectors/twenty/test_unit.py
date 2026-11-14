"""Unit tests of the Twenty connector's pure parts (twenty.md 1.4, 1.7, 2.2, 2.3, 3.2, 5.1). No database, no network."""

import os
import uuid
from datetime import datetime, timezone

import pytest

from consentvault.sync.connectors import twenty as tw
from consentvault.sync.connectors import twenty_api as api
from consentvault.sync.errors import CredentialError, TransportError


class Custody:
    def __init__(self):
        self.key = os.urandom(32)

    def wrap(self, org_id, data):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        n = os.urandom(12)
        return n + AESGCM(self.key).encrypt(n, data, org_id.encode())

    def unwrap(self, org_id, blob):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(self.key).decrypt(blob[:12], blob[12:], org_id.encode())


# signature (3.2): hex HMAC-SHA256 of "{timestamp}:{raw body}", read from Twenty 2.46.0's call-webhook job
def test_signature_known_vector_tampered_body_and_wrong_secret():
    secret, ts, body = b"s" * 32, "1793452584000", b'{"eventName":"person.updated","record":{"id":"r"}}'
    import hashlib
    import hmac

    vector = hmac.new(secret, b"1793452584000:" + body, hashlib.sha256).hexdigest()
    assert api.sign(secret, ts, body) == vector
    assert api.verify_signature(secret, ts, body, vector)
    assert not api.verify_signature(secret, ts, body.replace(b"updated", b"updatex"), vector)        # one flipped byte
    assert not api.verify_signature(secret, ts, b'{"eventName": "person.updated","record":{"id":"r"}}', vector)  # re-serialised
    assert not api.verify_signature(b"t" * 32, ts, body, vector)                                       # wrong secret
    assert not api.verify_signature(secret, "1793452584001", body, vector)                             # other timestamp
    assert not api.verify_signature(secret, ts, body, vector.upper())                                  # not the hex Twenty sends
    assert not api.verify_signature(secret, ts, body, "")


# the sequence rule (2.2): compared as integers, never as strings
@pytest.mark.parametrize("value,expected", [("9", 9), ("10", 10), ("007", 7), ("", None), ("9.5", None), ("-1", None),
                                            ("1e3", None), (None, None), (12, None), ("99999999999999999999", None)])
def test_integer_sequence_compare(value, expected):
    assert api.parse_seq(value) == expected
    assert api.parse_seq("10") > api.parse_seq("9")   # "9" > "10" as strings; never as integers


def test_contact_points_normalise_every_email_and_phone_and_cap_at_twenty():
    person = {"emails": {"primaryEmail": "Ann@Example.COM", "additionalEmails": ["b@example.com", "ann@example.com"]},
              "phones": {"primaryPhoneNumber": "(555) 210-0142", "primaryPhoneCallingCode": "+1",
                         "additionalPhones": [{"number": "5552100143", "callingCode": "+1"}, {"number": "nope", "callingCode": "+1"}]}}
    pts = api.contact_points(person)
    assert ("email", "ann@example.com") in pts and ("email", "b@example.com") in pts
    assert ("phone", "+15552100142") in pts and ("phone", "+15552100143") in pts
    assert len(pts) == 4                       # the duplicate email folds; the bad phone is not a point
    assert api.unmatchable_points(person) == 1  # and it is counted, never invisible
    many = {"emails": {"primaryEmail": "", "additionalEmails": [f"p{i}@example.com" for i in range(25)]}, "phones": {}}
    assert len(api.contact_points(many)) == api.MAX_POINTS and api.over_cap(many)


def test_derive_fields_blank_when_no_contact_contributes_and_denial_names_its_record():
    assert tw.derive_fields([]) == {f: None for f in api.OWNED}
    rid = uuid.uuid4()
    at = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
    rows = [{"channel": "email", "state": "permitted", "contributors": 2, "as_of_seq": 10, "last_check": "proceed",
             "last_check_at": at, "evidence_record": uuid.uuid4()},
            {"channel": "sms", "state": "denied", "contributors": 2, "as_of_seq": 10, "last_check": "proceed",
             "last_check_at": at, "evidence_record": rid}]
    got = tw.derive_fields(rows)
    assert got["cvStatusSms"] == "denied" and got["cvStatusEmail"] == "permitted" and got["cvStatusVoice"] == "none"
    assert got["cvStateSeq"] == "10" and got["cvLastCheck"] == "proceed" and got["cvLastCheckAt"].endswith("Z")
    assert got["cvEvidenceLink"] == f"https://app.consentvault.ai/evidence?record={rid}"


def test_hides_a_stop_only_when_twenty_is_less_restrictive_than_the_ledger():
    want = {**{f: "none" for f in api.STATUS_FIELDS.values()}, "cvStatusSms": "denied"}
    assert tw.hides_a_stop({"cvStatusSms": "permitted"}, want)
    assert tw.hides_a_stop({"cvStatusSms": None}, want)
    assert not tw.hides_a_stop({"cvStatusSms": "denied"}, want)


@pytest.mark.parametrize("status,stored,cls,outcome", [
    (401, False, "key_rejected", "dead"), (403, True, "key_rejected", "dead"), (408, False, "http_4xx", "retry"),
    (429, False, "http_4xx", "retry"), (500, False, "http_5xx", "retry"), (503, True, "http_5xx", "retry"),
    (404, False, "schema_changed", "retry"), (400, False, "http_4xx", "dead"), (422, True, "http_4xx", "dead")])
def test_one_error_class_per_status(status, stored, cls, outcome):
    with pytest.raises(api.TwentyError) as e:
        api.classify(api.CallResult("response", status), stored_id=stored)
    assert (e.value.error_class, e.value.outcome) == (cls, outcome)


def test_a_404_on_a_stored_id_is_not_an_error_and_door_answers_are_named():
    with pytest.raises(api.PersonGone):
        api.classify(api.CallResult("response", 404), stored_id=True)
    api.classify(api.CallResult("response", 204))
    for kind, cls in (("timeout", "timeout"), ("unreachable", "unreachable"), ("refused", "target_private")):
        with pytest.raises(api.TwentyError) as e:
            api.classify(api.CallResult(kind))
        assert e.value.error_class == cls
    with pytest.raises(TransportError):
        api.classify(api.CallResult("mystery"))


def test_secret_envelope_round_trip_wrong_authenticated_data_fails_and_no_plaintext_is_stored():
    c, org, sysid = Custody(), uuid.uuid4(), uuid.uuid4()
    secret = b"twenty-api-key-" + b"k" * 400          # longer than the 32 bytes the old sealer took
    wrapped, sealed = tw.seal_secret(c, org, sysid, "api_key", secret)
    assert secret not in wrapped + sealed
    assert tw.open_secret(c, org, sysid, "api_key", wrapped, sealed) == secret
    with pytest.raises(CredentialError):
        tw.open_secret(c, org, sysid, "webhook_secret", wrapped, sealed)   # purpose is bound
    with pytest.raises(CredentialError):
        tw.open_secret(c, org, uuid.uuid4(), "api_key", wrapped, sealed)   # system is bound
    with pytest.raises(CredentialError):
        tw.open_secret(c, org, sysid, "api_key", None, sealed)


def test_person_id_hash_is_keyed_and_stable():
    k1, k2 = os.urandom(32), os.urandom(32)
    assert tw.person_id_hash(k1, "p") == tw.person_id_hash(k1, "p")
    assert tw.person_id_hash(k1, "p") != tw.person_id_hash(k2, "p")
    import hashlib

    assert tw.person_id_hash(k1, "p") != hashlib.sha256(b"p").hexdigest()


def test_record_link_uses_the_route_confirmed_on_twenty():
    assert api.record_link("https://crm.example.com/", "abc") == "https://crm.example.com/object/person/abc"


def test_the_client_never_shows_its_key():
    c = api.TwentyClient("https://crm.example.com", "secret-key-value", transport=None)
    assert "secret-key-value" not in repr(c)
    assert "body" not in repr(api.CallResult("response", 200, {}, {"data": "x@example.com"}))


# ---- the egress door's /call, from the vault's side ---------------------------------------------------------------------------
class _Res:
    def __init__(self, status, body):
        self.status, self._b = status, body

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return None


def _door(status, body, seen):
    import json as _json

    def opener(req, timeout):
        seen.append((req.full_url, _json.loads(req.data), dict(req.header_items()), timeout))
        return _Res(status, _json.dumps(body).encode())
    return opener


def test_the_egress_transport_calls_the_door_and_reads_the_receivers_answer():
    from consentvault.sync.connectors.webhook import EgressTransport

    seen = []
    t = EgressTransport("https://egress.example.test", "door-secret",
                        opener=_door(200, {"receiver_status": 429, "receiver_headers": {"retry-after": "7"},
                                           "receiver_body": {"error": "slow"}}, seen))
    got = t.call("PATCH", "https://crm.example.test/rest/people/p", {"Authorization": "Bearer k"}, {"cvStatusSms": "denied"})
    assert (got.kind, got.status, got.headers, got.body) == ("response", 429, {"retry-after": "7"}, {"error": "slow"})
    url, wire, headers, timeout = seen[0]
    assert url == "https://egress.example.test/call" and timeout == 15
    assert wire == {"target_url": "https://crm.example.test/rest/people/p", "method": "PATCH",
                    "headers": {"Authorization": "Bearer k"}, "payload": {"cvStatusSms": "denied"}}
    assert headers.get("Authorization") == "Bearer door-secret"


@pytest.mark.parametrize("status,body,kind", [
    (504, {"error": "receiver_timeout"}, "timeout"), (502, {"error": "receiver_unreachable"}, "unreachable"),
    (403, {"error": "target_address_refused"}, "refused"), (400, {"error": "target_not_https"}, "refused")])
def test_the_doors_named_answers_become_named_call_results(status, body, kind):
    from consentvault.sync.connectors.webhook import EgressTransport

    got = EgressTransport("https://egress.example.test", "s", opener=_door(status, body, [])).call("GET", "https://x.test/", {}, None)
    assert got.kind == kind


def test_a_redirect_or_an_oversized_answer_is_the_receivers_fault_and_the_door_failing_is_the_doors():
    from consentvault.sync.connectors.webhook import EgressTransport

    got = EgressTransport("https://e.test", "s", opener=_door(502, {"error": "receiver_redirect", "receiver_status": 302}, [])
                          ).call("GET", "https://x.test/", {}, None)
    assert (got.kind, got.status) == ("response", 302)
    got = EgressTransport("https://e.test", "s", opener=_door(502, {"error": "receiver_body_too_large"}, [])
                          ).call("GET", "https://x.test/", {}, None)
    assert (got.kind, got.status) == ("response", 502)
    with pytest.raises(TransportError):
        EgressTransport("https://e.test", "s", opener=_door(401, {"error": "unauthorized"}, [])).call("GET", "https://x.test/", {}, None)
