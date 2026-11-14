"""The admin app accepts the write-once evidence store (records.md section 7: list exports are kept there under
records-exports/<export_id>; the capture pipeline is built from the same store object in api.CloudApiSettings)."""

from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.tenancy.admin_routes import AdminApp


def test_admin_app_holds_the_evidence_store_it_is_given_and_defaults_to_none(tmp_path):
    """records.md section 7 (exports are kept in the evidence store, key records-exports/<export_id>): the admin app takes the store."""
    store = LocalAppendOnlyEvidenceStore(tmp_path / "ev")
    kw = dict(connect=lambda: None, token_key=type("K", (), {"secret": b"x" * 32})())
    assert AdminApp(evidence_store=store, **kw).evidence_store is store
    assert AdminApp(**kw).evidence_store is None
