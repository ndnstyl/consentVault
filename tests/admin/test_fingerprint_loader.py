"""Integration pass: CustodyKeyAdapter reads the organisation's fingerprint secret from org_fingerprint_secret."""

import uuid

import pytest

from consentvault.ledger import record_tenant_event
from consentvault.tenancy.crypto import TenantCrypto
from consentvault.tenancy.errors import KeyProviderError
from consentvault.tenancy.keys_adapter import CustodyKeyAdapter
from consentvault.tenancy.tokens import mint_org_token, org_transaction


def _stored(vault, org_id):
    with vault.superuser() as su:
        return bytes(su.execute("SELECT wrapped FROM consentvault.org_fingerprint_secret WHERE org_id = %s",
                                (org_id,)).fetchone()["wrapped"])


def test_the_adapter_reads_each_organisations_own_fingerprint_secret(vault):
    a, boss_a = vault.org_with_admin("Acme", "boss@acme.example")
    b, _ = vault.org_with_admin("Bravo", "boss@bravo.example")
    adapter = CustodyKeyAdapter.from_database(vault.custody, vault.operator, vault.key)
    sa, sb = adapter.fingerprint_secret(uuid.UUID(a["org_id"])), adapter.fingerprint_secret(uuid.UUID(b["org_id"]))
    assert sa == vault.custody.unwrap(a["org_id"], _stored(vault, a["org_id"])) and len(sa) == 32
    assert sb == vault.custody.unwrap(b["org_id"], _stored(vault, b["org_id"])) and sa != sb
    with pytest.raises(KeyProviderError, match="no wrapped fingerprint secret"):
        adapter.fingerprint_secret(uuid.uuid4())
    # the same adapter drives the ledger writer: the fingerprint is keyed by the stored secret
    crypto = TenantCrypto(adapter)
    with vault.appconn() as c, org_transaction(c, mint_org_token(vault.key, a["org_id"], ["capture"], credential_id=None)):
        from consentvault import disclosure as disc
        sha = disc.register(c, "We may text you. Reply STOP to end.", "f", "en", ["sms"], ["marketing"])
        record_tenant_event(c, crypto, contact="+15555550142", event_type="grant", channels=["sms"],
                            purposes=["marketing"], method="checkbox", origin="consumer", disclosure_sha256=sha)
    with vault.superuser() as su:
        fp = su.execute("SELECT contact_fp FROM consentvault.event WHERE org_id = %s", (a["org_id"],)).fetchone()
    assert fp["contact_fp"] == crypto.contact_fingerprint(uuid.UUID(a["org_id"]), "phone", "+15555550142")
