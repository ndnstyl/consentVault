"""No contact point, IP address or token reaches a log line or an error message.

Fails the build two ways: the scrubber must redact each kind of value, and a real tenant flow logged at DEBUG with no
scrubber at all must not emit any of them (so the scrubber is a second line, not the only one).
"""

import logging
import os
import uuid

import pytest

from consentvault.errors import LedgerError
from consentvault.ledger import record_tenant_event
from consentvault.tenancy import logscrub
from consentvault.tenancy.crypto import TenantCrypto
from consentvault.tenancy.errors import TenantTokenError
from consentvault.tenancy.keys_protocol import WrappedKey
from consentvault.tenancy.tokens import TokenKey, mint_org_token, org_transaction

from isolation.harness import FakeKeyProvider, PHONE, build_tenancy

SENSITIVE = {
    "phone_e164": "+15555550142",
    "phone_us": "(555) 555-0142",
    "phone_dotted": "555.555.0142",
    "email": "jane.doe+promo@example.co.uk",
    "ipv4": "203.0.113.7",
    "ipv6": "2001:db8:85a3::8a2e:370:7334",
    "jwt": "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
    "bearer": "Bearer abcdefghijklmnop0123456789",
}


def _tenant_token() -> str:
    return mint_org_token(TokenKey("log-k", os.urandom(32)), uuid.uuid4(), ["capture"], credential_id=None)


@pytest.mark.parametrize("name", sorted(SENSITIVE))
def test_the_scrubber_redacts_each_kind_of_value(name):
    value = SENSITIVE[name]
    out = logscrub.scrub(f"before {value} after")
    assert value not in out and logscrub.REDACTED in out and out.startswith("before ") and out.endswith(" after")


def test_the_scrubber_redacts_tenant_tokens_and_secrets_in_key_value_form():
    token = _tenant_token()
    for text in (f"token {token}", f"password=hunter2hunter2", f"authorization: {token}", f"api_key=sk_live_123456"):
        out = logscrub.scrub(text)
        assert token not in out and "hunter2" not in out and "sk_live" not in out, out


def test_a_phone_number_glued_to_a_word_character_is_still_redacted():
    for text in ("key +13055550150_sms held", "dial +13055550150x now", "id=+13055550150_sms", "job +15551234567-retry failed",
                 "queue sms-18135550199 done"):
        out = logscrub.scrub(text)
        assert not any(d in out for d in ("3055550150", "5551234567", "8135550199")) and logscrub.REDACTED in out, out


def test_the_phone_rule_never_touches_a_uuid():
    """A UUID holding 10 digits in a row is never protected (it may be a number dressed as one); every other one survives."""
    import re
    import uuid as _uuid
    kept = 0
    for _ in range(20000):
        u = str(_uuid.uuid4())
        if re.search(r"\d{10}", u):
            assert "[redacted]" in logscrub.scrub(f"org {u}, ok")
            continue
        assert logscrub.scrub(f"org {u}, ok") == f"org {u}, ok"
        kept += 1
    assert kept > 19000


def test_the_scrubber_leaves_ordinary_operational_text_alone():
    text = "sync job finished: 42 rows in 1.5 s, org 3f2c8a1e-7b1a-4c3e-9f6e-2a1b3c4d5e6f, status 200"
    assert logscrub.scrub(text) == text


def test_an_installed_scrubber_redacts_messages_args_and_exceptions(caplog):
    caplog.set_level(logging.DEBUG)
    root = logging.getLogger()
    filt = logscrub.install(root)
    token = _tenant_token()
    try:
        log = logging.getLogger("consentvault.test.leaky")
        log.info("captured %s from %s with %s", SENSITIVE["phone_e164"], SENSITIVE["ipv4"], token)
        try:
            raise ValueError(f"bad contact {SENSITIVE['email']}")
        except ValueError:
            log.exception("capture failed for %s", SENSITIVE["phone_us"])
        assert logscrub.install(root) is filt  # idempotent
    finally:
        root.removeFilter(filt)
        for h in root.handlers:
            h.removeFilter(filt)
    text = caplog.text
    for value in (SENSITIVE["phone_e164"], SENSITIVE["ipv4"], token, SENSITIVE["email"], SENSITIVE["phone_us"]):
        assert value not in text, value
    assert len(caplog.records) == 2 and "capture failed for" in text


def test_a_tenant_flow_logged_at_debug_emits_no_contact_ip_or_token(dsn, pg_server, caplog, monkeypatch):
    # no scrubber at all: an entry point run by an earlier test may have installed the scrubbing record factory, so the plain one
    # is put back for this test (the code must emit nothing personal on its own; the scrubber is the second line)
    monkeypatch.setattr(logging, "_logRecordFactory", logging.LogRecord)
    caplog.set_level(logging.DEBUG)
    t = build_tenancy(dsn, pg_server["port"])
    token = t.token(t.a)
    with t.app() as app, org_transaction(app, token):
        record_tenant_event(app, t.crypto, contact=PHONE, event_type="revoke", channels=["sms"],
                            purposes=["marketing"], method="keyword", origin="consumer", client_ip="198.51.100.23")
    with pytest.raises(TenantTokenError) as refused:
        with t.app() as app, org_transaction(app, token[:-1] + ("0" if token[-1] != "0" else "1")):
            pass
    leaked = [r.getMessage() for r in caplog.records
              if any(v in r.getMessage() for v in (PHONE, "203.0.113.7", "198.51.100.23", token, t.key.secret.hex()))]
    assert leaked == []
    assert token[:40] not in str(refused.value) and token[:40] not in str(refused.value.__cause__)
    assert t.key.secret.hex() not in repr(t.key)


def test_a_database_refusal_of_an_encrypted_write_carries_no_contact_point(dsn, pg_server):
    t = build_tenancy(dsn, pg_server["port"])

    class WrongVersion(FakeKeyProvider):
        def wrap_data_key(self, org_id, data_key):
            return WrappedKey(super().wrap_data_key(org_id, data_key).ciphertext, 7)  # no such org key version

    provider = WrongVersion()
    provider.wrap_keys, provider.fp_secrets = t.provider.wrap_keys, t.provider.fp_secrets
    with t.app() as app:
        with pytest.raises(LedgerError) as refused:
            with org_transaction(app, t.token(t.a)):
                record_tenant_event(app, TenantCrypto(provider), contact="+15555550177", event_type="revoke",
                                    channels=["sms"], purposes=["marketing"], method="keyword", origin="consumer",
                                    client_ip="192.0.2.44")
    for text in (str(refused.value), str(refused.value.__cause__)):
        assert "+15555550177" not in text and "5550177" not in text and "192.0.2.44" not in text
