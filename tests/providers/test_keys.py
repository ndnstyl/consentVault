import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from consentvault.providers.errors import (
    DestructionWindowError, KeyDestroyedError, KeyExistsError, KeyNotFoundError, KeyPendingDestructionError,
    KeyProviderError, ProviderConfigError, ProviderTransportError, UnwrapError)
from consentvault.providers.keys import KeyProvider, LocalFileKeyProvider, OpenBaoKeyProvider

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
# A provider kept outside this repository (the managed service's) runs these same contract tests by naming a factory
# ``module:function`` that takes (tmp_path, clock) and returns a KeyProvider; see consentvault.providers.plugins.
ENV_CONTRACT_FACTORY = "CONSENTVAULT_KEY_PROVIDER_CONTRACT"


def external_contract_factory():
    import os

    spec = os.environ.get(ENV_CONTRACT_FACTORY)
    if not spec:
        return None
    from consentvault.providers.plugins import resolve_object

    return resolve_object(spec)


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now

    def advance(self, days):
        self.now += timedelta(days=days)


class FakeBao:
    """In-memory OpenBao transit: just enough of the HTTP surface the provider uses."""

    def __init__(self):
        self.keys = {}
        self.calls = []
        self.fail = None

    def __call__(self, method, path, body):
        self.calls.append((method, path))
        if self.fail:
            return self.fail, {"errors": ["boom"]}
        parts = path.split("/")  # '', v1, transit, op, name[, config]
        op, name = parts[3], parts[4]
        if op == "keys" and len(parts) == 5:
            if method == "GET":
                return (200, {"data": {"name": name}}) if name in self.keys else (404, {"errors": []})
            if method == "POST":
                self.keys[name] = {"deletion_allowed": body["deletion_allowed"], "type": body["type"]}
                return 204, {}
            if method == "DELETE":
                if not self.keys[name]["deletion_allowed"]:
                    return 400, {"errors": ["deletion_allowed is false"]}
                del self.keys[name]
                return 204, {}
        if op == "keys" and parts[5] == "config":
            self.keys[name]["deletion_allowed"] = body["deletion_allowed"]
            return 200, {}
        if name not in self.keys:
            return 404, {"errors": []}
        if op == "encrypt":
            return 200, {"data": {"ciphertext": f"vault:v1:{name}:{body['plaintext']}"}}
        if op == "decrypt":
            prefix = f"vault:v1:{name}:"
            if not body["ciphertext"].startswith(prefix):
                return 400, {"errors": ["invalid ciphertext"]}
            return 200, {"data": {"plaintext": body["ciphertext"][len(prefix):]}}
        raise AssertionError(path)


@pytest.fixture(params=["local", "bao", *(["external"] if external_contract_factory() else [])])
def provider(request, tmp_path):
    clock = Clock()
    if request.param == "external":
        p = external_contract_factory()(tmp_path, clock)
    elif request.param == "local":
        p = LocalFileKeyProvider(tmp_path / "keys", "correct horse battery", clock=clock)
    else:
        p = OpenBaoKeyProvider(FakeBao(), tmp_path / "ledger.json", clock=clock)
    p.clock = clock
    return p


DK = bytes(range(32))


def test_both_implement_the_interface(provider):
    assert isinstance(provider, KeyProvider)


def test_wrap_unwrap_roundtrip_and_isolation_between_orgs(provider):
    provider.create_org_key("org-a")
    provider.create_org_key("org-b")
    wrapped = provider.wrap("org-a", DK)
    assert DK not in wrapped
    assert provider.unwrap("org-a", wrapped) == DK
    with pytest.raises(UnwrapError):
        provider.unwrap("org-b", wrapped)


def test_create_twice_refused(provider):
    provider.create_org_key("org-a")
    with pytest.raises(KeyExistsError):
        provider.create_org_key("org-a")


def test_unknown_org_is_named_error(provider):
    with pytest.raises(KeyNotFoundError):
        provider.wrap("ghost", DK)
    with pytest.raises(KeyNotFoundError):
        provider.schedule_destruction("ghost")


@pytest.mark.parametrize("days", [0, 1, 29, -5, True])
def test_destruction_window_below_30_days_refused(provider, days):
    provider.create_org_key("org-a")
    with pytest.raises(DestructionWindowError):
        provider.schedule_destruction("org-a", window_days=days)
    assert provider.status("org-a").state == "active"


def test_default_window_is_30_days_and_key_is_unusable_while_pending(provider):
    provider.create_org_key("org-a")
    wrapped = provider.wrap("org-a", DK)
    st = provider.schedule_destruction("org-a")
    assert st.state == "pending" and st.destroy_at - st.scheduled_at == timedelta(days=30)
    with pytest.raises(KeyPendingDestructionError):
        provider.unwrap("org-a", wrapped)
    with pytest.raises(KeyPendingDestructionError):
        provider.wrap("org-a", DK)
    with pytest.raises(KeyProviderError):
        provider.schedule_destruction("org-a")


def test_cancel_restores_use(provider):
    provider.create_org_key("org-a")
    wrapped = provider.wrap("org-a", DK)
    provider.schedule_destruction("org-a")
    assert provider.cancel_destruction("org-a").state == "active"
    assert provider.unwrap("org-a", wrapped) == DK


def test_cancel_without_schedule_is_error(provider):
    provider.create_org_key("org-a")
    with pytest.raises(KeyProviderError):
        provider.cancel_destruction("org-a")


def test_nothing_destroyed_before_window_elapses(provider):
    provider.create_org_key("org-a")
    provider.schedule_destruction("org-a")
    provider.clock.advance(29)
    assert provider.process_destructions() == []
    assert provider.is_destroyed("org-a") is False


def test_destruction_after_window_reports_destroyed_and_is_final(provider):
    provider.create_org_key("org-a")
    wrapped = provider.wrap("org-a", DK)
    provider.schedule_destruction("org-a")
    provider.clock.advance(30)
    assert provider.process_destructions() == ["org-a"]
    assert provider.is_destroyed("org-a") is True
    st = provider.status("org-a")
    assert st.state == "destroyed" and st.destroyed_at == provider.clock.now
    with pytest.raises(KeyDestroyedError):
        provider.unwrap("org-a", wrapped)
    with pytest.raises(KeyDestroyedError):
        provider.cancel_destruction("org-a")
    with pytest.raises(KeyDestroyedError):
        provider.create_org_key("org-a")
    assert provider.process_destructions() == []


def test_schedule_survives_a_new_provider_instance(tmp_path):
    clock = Clock()
    a = LocalFileKeyProvider(tmp_path, "correct horse battery", clock=clock)
    a.create_org_key("org-a")
    wrapped = a.wrap("org-a", DK)
    b = LocalFileKeyProvider(tmp_path, "correct horse battery", clock=clock)
    assert b.unwrap("org-a", wrapped) == DK
    b.schedule_destruction("org-a")
    assert a.status("org-a").state == "pending"


def test_unsafe_org_ids_refused(provider):
    for bad in ("../x", "a/b", "", "a b", "x" * 65):
        with pytest.raises(ProviderConfigError):
            provider.create_org_key(bad)


@pytest.mark.parametrize("bad", [b"", b"short", bytes(65)])
def test_bad_data_key_size_refused(provider, bad):
    provider.create_org_key("org-a")
    with pytest.raises(KeyProviderError):
        provider.wrap("org-a", bad)


# local-file specifics
def test_local_provider_states_it_has_no_provable_destruction(tmp_path):
    p = LocalFileKeyProvider(tmp_path, "correct horse battery")
    assert p.provable_destruction is False
    assert "no provable destruction" in LocalFileKeyProvider.__doc__.lower()
    assert "no provable destruction" in p.destruction_caveat


def test_local_key_file_is_sealed_and_private(tmp_path):
    p = LocalFileKeyProvider(tmp_path, "correct horse battery")
    p.create_org_key("org-a")
    f = tmp_path / "org-a.key.json"
    assert (f.stat().st_mode & 0o777) == 0o600
    assert set(json.loads(f.read_text())) == {"v", "salt", "nonce", "ct"}


def test_local_wrong_passphrase_is_named_error(tmp_path):
    LocalFileKeyProvider(tmp_path, "correct horse battery").create_org_key("org-a")
    other = LocalFileKeyProvider(tmp_path, "different passphrase!")
    with pytest.raises(KeyProviderError, match="wrong passphrase"):
        other.wrap("org-a", DK)


def test_local_short_passphrase_refused(tmp_path):
    with pytest.raises(ProviderConfigError):
        LocalFileKeyProvider(tmp_path, "short")


def test_local_destruction_removes_file_but_copy_still_decrypts(tmp_path):
    """The reason the provider says 'no provable destruction': a copy made earlier survives."""
    clock = Clock()
    p = LocalFileKeyProvider(tmp_path / "live", "correct horse battery", clock=clock)
    p.create_org_key("org-a")
    wrapped = p.wrap("org-a", DK)
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "org-a.key.json").write_bytes((tmp_path / "live" / "org-a.key.json").read_bytes())
    p.schedule_destruction("org-a")
    clock.advance(31)
    p.process_destructions()
    assert not (tmp_path / "live" / "org-a.key.json").exists()
    assert LocalFileKeyProvider(backup, "correct horse battery").unwrap("org-a", wrapped) == DK


def test_local_tampered_wrapped_key_is_unwrap_error(tmp_path):
    p = LocalFileKeyProvider(tmp_path, "correct horse battery")
    p.create_org_key("org-a")
    w = bytearray(p.wrap("org-a", DK))
    w[-1] ^= 1
    with pytest.raises(UnwrapError):
        p.unwrap("org-a", bytes(w))
    with pytest.raises(UnwrapError):
        p.unwrap("org-a", b"tiny")


def test_local_corrupt_ledger_is_loud(tmp_path):
    p = LocalFileKeyProvider(tmp_path, "correct horse battery")
    p.create_org_key("org-a")
    (tmp_path / "destruction.json").write_text("{not json")
    with pytest.raises(KeyProviderError):
        p.status("org-a")


# OpenBao specifics
def test_openbao_default_does_not_claim_provable_destruction(tmp_path):
    assert OpenBaoKeyProvider(FakeBao(), tmp_path / "l.json").provable_destruction is False
    assert OpenBaoKeyProvider(FakeBao(), tmp_path / "l.json", provable_destruction=True).provable_destruction is True


def test_openbao_key_is_created_non_exportable_and_not_deletable(tmp_path):
    bao = FakeBao()
    p = OpenBaoKeyProvider(bao, tmp_path / "l.json")
    ref = p.create_org_key("org-a")
    assert ref == "openbao:transit/cv-org-org-a"
    assert bao.keys["cv-org-org-a"] == {"deletion_allowed": False, "type": "aes256-gcm96"}


def test_openbao_destruction_deletes_on_server(tmp_path):
    clock = Clock()
    bao = FakeBao()
    p = OpenBaoKeyProvider(bao, tmp_path / "l.json", clock=clock)
    p.create_org_key("org-a")
    p.schedule_destruction("org-a")
    assert "cv-org-org-a" in bao.keys
    clock.advance(30)
    p.process_destructions()
    assert bao.keys == {}


def test_openbao_ledger_destroyed_but_key_still_there_is_loud(tmp_path):
    clock = Clock()
    bao = FakeBao()
    p = OpenBaoKeyProvider(bao, tmp_path / "l.json", clock=clock)
    p.create_org_key("org-a")
    p.schedule_destruction("org-a")
    clock.advance(30)
    p.process_destructions()
    bao.keys["cv-org-org-a"] = {"deletion_allowed": False, "type": "x"}
    with pytest.raises(KeyProviderError, match="still holds"):
        p.is_destroyed("org-a")


def test_openbao_server_errors_are_transport_errors(tmp_path):
    bao = FakeBao()
    p = OpenBaoKeyProvider(bao, tmp_path / "l.json")
    p.create_org_key("org-a")
    bao.fail = 503
    with pytest.raises(ProviderTransportError):
        p.wrap("org-a", DK)
    bao.fail = 403
    with pytest.raises(KeyProviderError):
        p.wrap("org-a", DK)


def test_openbao_garbage_ciphertext_is_unwrap_error(tmp_path):
    p = OpenBaoKeyProvider(FakeBao(), tmp_path / "l.json")
    p.create_org_key("org-a")
    with pytest.raises(UnwrapError):
        p.unwrap("org-a", b"vault:v1:nonsense")
    with pytest.raises(UnwrapError):
        p.unwrap("org-a", b"\xff\xfe")


def test_openbao_transport_requires_https_or_loopback():
    from consentvault.providers.keys import UrllibBaoTransport
    with pytest.raises(ProviderConfigError):
        UrllibBaoTransport("http://bao.example.com:8200", "t")
    with pytest.raises(ProviderConfigError):
        UrllibBaoTransport("https://bao.example.com", "")
    UrllibBaoTransport("http://127.0.0.1:8200", "t")
