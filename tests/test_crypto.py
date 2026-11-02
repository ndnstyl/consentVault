"""Field encryption: per-contact keys, ciphertexts bound to organisation, record and column, keyed hashes."""

import hashlib
import os
import uuid

import pytest

from consentvault.tenancy import crypto as tc
from consentvault.tenancy.crypto import MAX_FINGERPRINT_CACHE_SECONDS, TenantCrypto
from consentvault.tenancy.errors import FieldCryptoError, FieldDecryptError, KeyProviderError
from consentvault.tenancy.keys_protocol import KeyProvider, WrappedKey

from isolation.harness import FakeKeyProvider

A, B = uuid.uuid4(), uuid.uuid4()
EVENT = str(uuid.uuid4())


@pytest.fixture
def provider():
    p = FakeKeyProvider()
    p.add_org(A)
    p.add_org(B)
    return p


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_a_field_round_trips_and_every_encryption_uses_a_fresh_nonce():
    dk = os.urandom(32)
    one = tc.encrypt_field(dk, A, EVENT, "contact_norm", "+15555550100")
    two = tc.encrypt_field(dk, A, EVENT, "contact_norm", "+15555550100")
    assert one != two and b"+15555550100" not in one
    assert tc.decrypt_text(dk, A, EVENT, "contact_norm", one) == "+15555550100"
    assert tc.decrypt_field(dk, A, EVENT, "blob", tc.encrypt_field(dk, A, EVENT, "blob", b"\x00\x01")) == b"\x00\x01"


@pytest.mark.parametrize("org,record,column", [(B, EVENT, "contact_norm"), (A, str(uuid.uuid4()), "contact_norm"),
                                               (A, EVENT, "client_ip")])
def test_a_ciphertext_moved_to_another_organisation_record_or_column_fails(org, record, column):
    dk = os.urandom(32)
    blob = tc.encrypt_field(dk, A, EVENT, "contact_norm", "+15555550100")
    with pytest.raises(FieldDecryptError):
        tc.decrypt_field(dk, org, record, column, blob)


def test_a_wrong_key_a_flipped_byte_or_a_bad_envelope_fails_by_name():
    dk = os.urandom(32)
    blob = tc.encrypt_field(dk, A, EVENT, "contact_norm", "x")
    with pytest.raises(FieldDecryptError):
        tc.decrypt_field(os.urandom(32), A, EVENT, "contact_norm", blob)
    flipped = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(FieldDecryptError):
        tc.decrypt_field(dk, A, EVENT, "contact_norm", flipped)
    with pytest.raises(FieldCryptoError, match="envelope"):
        tc.decrypt_field(dk, A, EVENT, "contact_norm", b"\x02" + blob[1:])
    with pytest.raises(FieldCryptoError, match="envelope"):
        tc.decrypt_field(dk, A, EVENT, "contact_norm", b"\x01short")
    with pytest.raises(FieldCryptoError):
        tc.encrypt_field(b"short", A, EVENT, "contact_norm", "x")
    with pytest.raises(FieldCryptoError):
        tc.encrypt_field(dk, A, "a\x00b", "contact_norm", "x")
    with pytest.raises(FieldCryptoError):
        tc.encrypt_field(dk, "not-a-uuid", EVENT, "contact_norm", "x")


def test_the_payload_hash_is_keyed_by_the_contact_key():
    dk1, dk2, payload = os.urandom(32), os.urandom(32), b'{"phone":"+15555550100"}'
    assert tc.payload_mac(dk1, payload) == tc.payload_mac(dk1, payload)
    assert tc.payload_mac(dk1, payload) != tc.payload_mac(dk2, payload)
    assert tc.payload_mac(dk1, payload) != hashlib.sha256(payload).hexdigest()


def test_fingerprints_are_stable_per_organisation_and_unlinkable_across_them(provider):
    c = TenantCrypto(provider)
    fa = c.contact_fingerprint(A, "phone", "+15555550100")
    assert fa == c.contact_fingerprint(A, "phone", "+15555550100")
    assert fa != c.contact_fingerprint(B, "phone", "+15555550100")
    assert fa != c.contact_fingerprint(A, "email", "+15555550100")
    assert fa != c.subject_fingerprint(A, "+15555550100")
    assert len(fa) == 64 and int(fa, 16) >= 0


def test_the_fingerprint_secret_is_cached_at_most_fifteen_minutes(provider):
    clock = Clock()
    c = TenantCrypto(provider, clock=clock)
    for _ in range(5):
        c.contact_fingerprint(A, "phone", "+15555550100")
    assert provider.calls["fingerprint_secret"] == 1
    clock.now += MAX_FINGERPRINT_CACHE_SECONDS - 1
    c.contact_fingerprint(A, "phone", "+15555550100")
    assert provider.calls["fingerprint_secret"] == 1
    clock.now += 1
    c.contact_fingerprint(A, "phone", "+15555550100")
    assert provider.calls["fingerprint_secret"] == 2
    c.forget(A)
    c.contact_fingerprint(A, "phone", "+15555550100")
    assert provider.calls["fingerprint_secret"] == 3
    with pytest.raises(KeyProviderError):
        TenantCrypto(provider, cache_seconds=MAX_FINGERPRINT_CACHE_SECONDS + 1)


def test_each_contact_gets_its_own_random_key_wrapped_per_organisation(provider):
    c = TenantCrypto(provider)
    k1, k2 = c.new_contact_key(A), c.new_contact_key(A)
    assert k1.data_key != k2.data_key and len(k1.data_key) == 32
    assert c.open_contact_key(A, k1.wrapped) == k1.data_key
    with pytest.raises(KeyProviderError):
        c.open_contact_key(B, k1.wrapped)
    assert k1.data_key.hex() not in repr(k1) and "redacted" in repr(k1)


def test_a_failing_or_misbehaving_provider_raises_by_name(provider):
    class Broken(FakeKeyProvider):
        def fingerprint_secret(self, org_id):
            raise RuntimeError("kms unreachable")

        def wrap_data_key(self, org_id, data_key):
            return b"not a WrappedKey"

        def unwrap_data_key(self, org_id, wrapped):
            return b"short"

    c = TenantCrypto(Broken())
    with pytest.raises(KeyProviderError, match=r"fingerprint_secret failed: RuntimeError") as named_error:
        c.contact_fingerprint(A, "phone", "+15555550100")
    assert "kms unreachable" not in str(named_error.value)  # the provider's own text never travels; its class does
    with pytest.raises(KeyProviderError, match="WrappedKey"):
        c.new_contact_key(A)
    with pytest.raises(KeyProviderError, match="32 bytes"):
        c.open_contact_key(A, WrappedKey(b"x", 1))
    with pytest.raises(KeyProviderError, match="does not implement"):
        TenantCrypto(object())
    assert isinstance(provider, KeyProvider)


def test_field_encryption_runs_end_to_end_on_the_local_file_key_provider(dsn, pg_server, tmp_path):
    from datetime import datetime, timedelta, timezone

    from consentvault.ledger import _plaintext_breaks, record_tenant_event, verify_chain
    from consentvault.providers.keys import LocalFileKeyProvider
    from consentvault.tenancy.keys_adapter import CustodyKeyAdapter
    from consentvault.tenancy.tokens import org_transaction
    from isolation.harness import build_tenancy

    t = build_tenancy(dsn, pg_server["port"])
    now = [datetime.now(timezone.utc)]
    custody = LocalFileKeyProvider(tmp_path / "keys", "a long test passphrase", clock=lambda: now[0])
    stored: dict = {}
    stored_display: dict = {}
    adapter = CustodyKeyAdapter(custody, lambda org: stored[org], lambda org: stored_display[org])
    for org in (t.a, t.b):
        custody.create_org_key(str(org.org_id))
        stored[org.org_id] = adapter.new_fingerprint_secret(org.org_id)
        stored_display[org.org_id] = adapter.new_display_key(org.org_id)
    assert isinstance(adapter, KeyProvider) and adapter.provable_destruction is False
    crypto = TenantCrypto(adapter)

    for org in (t.a, t.b):
        with t.app() as app, org_transaction(app, t.token(org)):
            e = record_tenant_event(app, crypto, contact="+15555550188", event_type="revoke", channels=["sms"],
                                    purposes=["marketing"], method="keyword", origin="consumer",
                                    client_ip="198.51.100.9", payload=b"STOP")
            assert e.seq == 3
    assert crypto.contact_fingerprint(t.a.org_id, "phone", "+15555550188") != \
        crypto.contact_fingerprint(t.b.org_id, "phone", "+15555550188")
    with t.superuser() as owner:
        # every link verifies; the plaintext of the rows this provider wrote verifies under it. The harness rows were
        # sealed under another provider and keep their keys: deleting a key by hand is a break, never an erasure
        assert verify_chain(owner) == []
        mine = owner.execute("SELECT * FROM consentvault.event WHERE seq = 3 ORDER BY org_id").fetchall()
        assert len(mine) == 2 and [b for r in mine for b in _plaintext_breaks(owner, crypto, r)] == []
        owner.execute("DELETE FROM consentvault.contact_key WHERE contact_fp = %s",
                      (crypto.contact_fingerprint(t.b.org_id, "phone", "+15555550188"),))
        b_row = next(r for r in mine if r["org_id"] == t.b.org_id)
        assert [x.reason for x in _plaintext_breaks(owner, crypto, b_row)] == ["contact_key_missing"]

    custody.schedule_destruction(str(t.a.org_id))
    now[0] += timedelta(days=31)
    assert custody.process_destructions() == [str(t.a.org_id)]
    crypto.forget()
    with pytest.raises(KeyProviderError, match="KeyDestroyedError"):
        crypto.contact_fingerprint(t.a.org_id, "phone", "+15555550188")
    with t.superuser() as owner:
        held = owner.execute("SELECT wrapped_key, key_version FROM consentvault.contact_key WHERE org_id = %s"
                             " AND contact_fp = %s", (t.a.org_id, mine[0]["contact_fp"] if mine[0]["org_id"] == t.a.org_id
                                                      else mine[1]["contact_fp"])).fetchone()
    with pytest.raises(KeyProviderError, match="KeyDestroyedError"):
        crypto.open_contact_key(t.a.org_id, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
    assert crypto.contact_fingerprint(t.b.org_id, "phone", "+15555550188")  # the other organisation is untouched
    with pytest.raises(KeyProviderError, match="version"):
        adapter.unwrap_data_key(t.b.org_id, WrappedKey(b"x" * 60, 2))
