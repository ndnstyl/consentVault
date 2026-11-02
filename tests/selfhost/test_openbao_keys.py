"""OpenBaoKeyProvider against the durable (raft, sealed at rest) OpenBao of the stack, with the vault's narrow token."""

import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from consentvault.providers.errors import KeyDestroyedError, KeyPendingDestructionError, UnwrapError
from consentvault.providers.keys import OpenBaoKeyProvider, UrllibBaoTransport

from .conftest import SELFHOST, http_json


@pytest.fixture(scope="module")
def bao_addr(settings):
    return f"http://127.0.0.1:{settings['OPENBAO_PORT']}"


@pytest.fixture(scope="module")
def bao_token():
    f = Path(os.environ.get("SELFHOST_SECRETS_DIR", SELFHOST / "secrets")) / "openbao-vault-token"
    if not f.is_file():
        pytest.fail(f"{f} is missing: run deploy/selfhost/bin/openbao-bootstrap.sh")
    return f.read_text().strip()


class Clock:
    def __init__(self):
        self.now = datetime.now(timezone.utc)

    def __call__(self):
        return self.now


def test_openbao_is_durable_not_dev_mode(bao_addr):
    status, doc, _ = http_json("GET", f"{bao_addr}/v1/sys/seal-status")
    assert status == 200
    assert doc["initialized"] is True and doc["sealed"] is False
    assert doc["storage_type"] == "raft"  # dev mode is in-memory; raft is on the volume


def test_vault_token_cannot_administer_anything_else(bao_addr, bao_token):
    h = {"X-Vault-Token": bao_token}
    for path in ("/v1/sys/policies/acl/consentvault", "/v1/sys/mounts", "/v1/auth/token/create"):
        status, _, _ = http_json("GET", bao_addr + path, headers=h)
        assert status == 403, path


def test_wrap_unwrap_and_destruction_lifecycle(bao_addr, bao_token, tmp_path):
    clock = Clock()
    kp = OpenBaoKeyProvider(UrllibBaoTransport(bao_addr, bao_token), tmp_path / "destruction.json", clock=clock)
    org = "org-" + uuid.uuid4().hex[:10]
    kp.create_org_key(org)
    dek = os.urandom(32)
    wrapped = kp.wrap(org, dek)
    assert wrapped != dek and kp.unwrap(org, wrapped) == dek
    with pytest.raises(UnwrapError):
        kp.unwrap(org, wrapped[:-4] + b"AAAA")
    kp.schedule_destruction(org)
    with pytest.raises(KeyPendingDestructionError):
        kp.wrap(org, dek)
    assert kp.process_destructions() == []  # window not elapsed
    kp.cancel_destruction(org)
    assert kp.unwrap(org, wrapped) == dek
    kp.schedule_destruction(org)
    clock.now += timedelta(days=400)
    assert kp.process_destructions() == [org]
    assert kp.is_destroyed(org) is True
    with pytest.raises(KeyDestroyedError):
        kp.unwrap(org, wrapped)
    status, _, _ = http_json("GET", f"{bao_addr}/v1/transit/keys/cv-org-{org}", headers={"X-Vault-Token": bao_token})
    assert status == 404  # gone from the server, not only marked in the ledger


def test_no_provable_destruction_unless_declared(bao_addr, bao_token, tmp_path):
    kp = OpenBaoKeyProvider(UrllibBaoTransport(bao_addr, bao_token), tmp_path / "d.json")
    assert kp.provable_destruction is False
