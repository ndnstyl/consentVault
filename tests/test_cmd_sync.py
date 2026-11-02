"""``consentvault sync-worker``: the start command for the suppression sync worker, wired by config to a key provider
(OpenBao in the self-host, the managed service's plugin in the cloud), the egress transport, and the database."""

import sys
import types

import pytest

from consentvault import cli
from consentvault.errors import ConfigError
from consentvault.providers.keys import KeyProvider

from providers.test_plugins import GoodProvider

EGRESS = "https" + "://egress.example/"


@pytest.fixture
def env(tmp_path, monkeypatch):
    mod = types.ModuleType("cv_sync_plugin")
    mod.GoodProvider = GoodProvider
    monkeypatch.setitem(sys.modules, "cv_sync_plugin", mod)
    key = tmp_path / "tenant.key"
    key.write_text("ab" * 32)
    egress = tmp_path / "egress.secret"
    egress.write_text("egress-secret\n")
    values = {"CONSENTVAULT_DSN": "postgresql://w@127.0.0.1:1/x", "CONSENTVAULT_OPERATOR_DSN": "postgresql://c@127.0.0.1:1/x",
              "CONSENTVAULT_KEY_PROVIDER": "cv_sync_plugin:GoodProvider", "CONSENTVAULT_TOKEN_KEY_ID": "k1",
              "CONSENTVAULT_TOKEN_KEY_FILE": str(key), "CONSENTVAULT_EGRESS_URL": EGRESS,
              "CONSENTVAULT_EGRESS_SECRET_FILE": str(egress)}
    for k, v in values.items():
        monkeypatch.setenv(k, v)
    return values


def test_the_worker_is_built_from_config_with_the_named_key_provider(env):
    from consentvault import cmd_sync
    from consentvault.config import load_config

    worker, connect = cmd_sync.build_worker(load_config(env=env), env)
    assert isinstance(worker.custody, GoodProvider) and isinstance(worker.custody, KeyProvider)
    assert worker.transport.egress_url == EGRESS and worker.transport.secret == "egress-secret"
    assert callable(connect)
    # the Twenty connector calls through the same door (its /call); without it Twenty pushes would only wait, named
    assert worker.twenty is not None and worker.twenty.transport is worker.transport


@pytest.mark.parametrize("drop", ["CONSENTVAULT_KEY_PROVIDER", "CONSENTVAULT_TOKEN_KEY_FILE", "CONSENTVAULT_TOKEN_KEY_ID",
                                  "CONSENTVAULT_EGRESS_URL", "CONSENTVAULT_EGRESS_SECRET_FILE"])
def test_a_missing_setting_is_named_and_nothing_runs(env, drop):
    from consentvault import cmd_sync
    from consentvault.config import load_config

    env = {k: v for k, v in env.items() if k != drop}
    with pytest.raises(ConfigError, match=drop):
        cmd_sync.build_worker(load_config(env=env), env)


def test_once_runs_one_pass_on_the_configured_connection(env, monkeypatch):
    from consentvault import cmd_sync

    ran = []

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(cmd_sync, "_open", lambda connect: FakeConn())
    monkeypatch.setattr("consentvault.sync.worker.SyncWorker.run_once",
                        lambda self, conn, connect=None: ran.append((conn, connect)) or "report")
    assert cli.main(["sync-worker", "--once"]) == cli.EXIT_OK
    assert len(ran) == 1 and callable(ran[0][1])


def test_the_command_is_registered():
    cli.build_parser()
    assert "sync-worker" in cli.REGISTRY
