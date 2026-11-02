"""Per-organisation key rotation in both open key providers: a new version wraps new keys, old wraps still open until
their version is destroyed, a re-wrap keeps the data key, and a version is destroyed only once it is retired."""

import pytest

from consentvault.providers.errors import KeyDestroyedError, KeyPendingDestructionError, KeyProviderError, UnwrapError
from consentvault.providers.keys import LocalFileKeyProvider, OpenBaoKeyProvider, wrapped_version

from .test_keys import Clock, FakeBao, external_contract_factory

DK = bytes(range(32))
DK2 = bytes(range(1, 33))


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


def test_a_new_org_key_is_version_1_and_wraps_in_the_unchanged_format(provider):
    provider.create_org_key("org-a")
    assert provider.active_version("org-a") == 1
    blob = provider.wrap("org-a", DK)
    assert wrapped_version(blob) == 1
    assert provider.unwrap("org-a", blob) == DK


def test_rotation_makes_a_new_active_version_and_old_wraps_still_open(provider):
    provider.create_org_key("org-a")
    old = provider.wrap("org-a", DK)
    version, ref = provider.rotate_org_key("org-a")
    assert version == 2 and ref and provider.active_version("org-a") == 2
    new = provider.wrap("org-a", DK2)
    assert wrapped_version(new) == 2 and wrapped_version(old) == 1
    assert provider.unwrap("org-a", old) == DK
    assert provider.unwrap("org-a", new) == DK2
    assert provider.versions("org-a") == {1: "retired", 2: "active"}


def test_a_rewrap_moves_a_wrap_to_the_active_version_and_keeps_the_data_key(provider):
    provider.create_org_key("org-a")
    old = provider.wrap("org-a", DK)
    provider.rotate_org_key("org-a")
    moved = provider.rewrap("org-a", old)
    assert wrapped_version(moved) == 2 and provider.unwrap("org-a", moved) == DK
    assert provider.rewrap("org-a", moved) == moved  # already under the active version: unchanged


def test_the_active_version_is_never_destroyed(provider):
    provider.create_org_key("org-a")
    with pytest.raises(KeyProviderError, match="active"):
        provider.destroy_version("org-a", 1)
    provider.rotate_org_key("org-a")
    with pytest.raises(KeyProviderError, match="active"):
        provider.destroy_version("org-a", 2)


def test_destroying_a_retired_version_shreds_its_wraps_only_and_is_idempotent(provider):
    provider.create_org_key("org-a")
    old = provider.wrap("org-a", DK)
    provider.rotate_org_key("org-a")
    moved = provider.rewrap("org-a", old)
    assert provider.destroy_version("org-a", 1) is True
    assert provider.destroy_version("org-a", 1) is False
    with pytest.raises(KeyDestroyedError):
        provider.unwrap("org-a", old)
    assert provider.unwrap("org-a", moved) == DK
    assert provider.versions("org-a") == {1: "destroyed", 2: "active"}
    assert provider.status("org-a").state == "active"


def test_a_rotated_wrap_of_one_org_never_opens_for_another(provider):
    provider.create_org_key("org-a")
    provider.create_org_key("org-b")
    provider.rotate_org_key("org-a")
    provider.rotate_org_key("org-b")
    blob = provider.wrap("org-a", DK)
    with pytest.raises(UnwrapError):
        provider.unwrap("org-b", blob)
    assert provider.versions("org-b") == {1: "retired", 2: "active"}


def test_rotation_is_refused_while_the_org_key_is_scheduled_for_destruction(provider):
    provider.create_org_key("org-a")
    provider.schedule_destruction("org-a")
    with pytest.raises(KeyPendingDestructionError):
        provider.rotate_org_key("org-a")


def test_destroying_the_org_destroys_every_version(provider):
    provider.create_org_key("org-a")
    old = provider.wrap("org-a", DK)
    provider.rotate_org_key("org-a")
    new = provider.wrap("org-a", DK2)
    provider.schedule_destruction("org-a")
    provider.clock.advance(31)
    assert provider.process_destructions() == ["org-a"]
    assert provider.is_destroyed("org-a")
    for blob in (old, new):
        with pytest.raises(KeyDestroyedError):
            provider.unwrap("org-a", blob)
    with pytest.raises(KeyDestroyedError):
        provider.rotate_org_key("org-a")


def test_rotation_survives_a_new_provider_instance(tmp_path):
    p = LocalFileKeyProvider(tmp_path / "keys", "correct horse battery")
    p.create_org_key("org-a")
    p.rotate_org_key("org-a")
    p.destroy_version("org-a", 1)
    again = LocalFileKeyProvider(tmp_path / "keys", "correct horse battery")
    assert again.active_version("org-a") == 2 and again.versions("org-a") == {1: "destroyed", 2: "active"}
    assert wrapped_version(again.wrap("org-a", DK)) == 2


def test_an_altered_versioned_wrap_is_an_unwrap_error(tmp_path):
    provider = LocalFileKeyProvider(tmp_path / "keys", "correct horse battery")
    provider.create_org_key("org-a")
    provider.rotate_org_key("org-a")
    blob = bytearray(provider.wrap("org-a", DK))
    blob[-1] ^= 1
    with pytest.raises(UnwrapError):
        provider.unwrap("org-a", bytes(blob))


def test_a_wrap_naming_a_version_that_does_not_exist_is_refused_by_name(provider):
    provider.create_org_key("org-a")
    provider.rotate_org_key("org-a")
    blob = provider.wrap("org-a", DK)
    forged = blob[:4] + (9).to_bytes(4, "big") + blob[8:]
    with pytest.raises(KeyProviderError, match="version 9"):
        provider.unwrap("org-a", forged)
