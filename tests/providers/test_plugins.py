"""The key-provider plugin hook: config names a KeyProvider kept outside this repository by import path or entry point.
Anything that is not a KeyProvider subclass is refused by name; nothing here knows about any cloud."""

import sys
import types

import pytest

from consentvault.errors import ConfigError
from consentvault.providers import plugins
from consentvault.providers.keys import KeyProvider, OpenBaoKeyProvider

from .test_keys import FakeBao


class GoodProvider(KeyProvider):
    provable_destruction = True

    def __init__(self, env):
        self.env = env

    @classmethod
    def from_environment(cls, env):
        return cls(dict(env))

    create_org_key = wrap = unwrap = schedule_destruction = cancel_destruction = None
    process_destructions = status = is_destroyed = None


class NotAProvider:
    @classmethod
    def from_environment(cls, env):
        return cls()


class NoFactory(GoodProvider):
    from_environment = None


class LiesAboutItself(GoodProvider):
    @classmethod
    def from_environment(cls, env):
        return object()


@pytest.fixture
def plugin_module(monkeypatch):
    mod = types.ModuleType("cv_test_plugin")
    for c in (GoodProvider, NotAProvider, NoFactory, LiesAboutItself):
        setattr(mod, c.__name__, c)
    mod.not_a_class = lambda env: GoodProvider(env)
    monkeypatch.setitem(sys.modules, "cv_test_plugin", mod)
    return mod


def test_a_dotted_path_names_an_external_provider_built_from_the_environment(plugin_module):
    p = plugins.load_key_provider("cv_test_plugin:GoodProvider", env={"X": "1"})
    assert isinstance(p, GoodProvider) and p.env == {"X": "1"}


@pytest.mark.parametrize("spec,match", [
    ("cv_test_plugin:NotAProvider", "not a KeyProvider subclass"),
    ("cv_test_plugin:not_a_class", "not a KeyProvider subclass"),
    ("cv_test_plugin:NoFactory", "from_environment"),
    ("cv_test_plugin:LiesAboutItself", "did not return a KeyProvider"),
    ("cv_test_plugin:Missing", "has no attribute"),
    ("no_such_module_cv:Thing", "cannot be imported"),
    ("cv_test_plugin", "module:Class"),
    ("", "no key provider"),
    ("entrypoint:not-installed", "no installed entry point"),
])
def test_anything_that_is_not_a_key_provider_is_refused_by_name(plugin_module, spec, match):
    with pytest.raises(ConfigError, match=match):
        plugins.load_key_provider(spec, env={})


def test_an_entry_point_names_a_provider_class(plugin_module, monkeypatch):
    class EP:
        name, group, value = "aws-kms", plugins.ENTRY_POINT_GROUP, "cv_test_plugin:GoodProvider"

        def load(self):
            return GoodProvider

    monkeypatch.setattr(plugins, "_entry_points", lambda: [EP()])
    assert isinstance(plugins.load_key_provider("entrypoint:aws-kms", env={}), GoodProvider)


def test_openbao_is_built_in_and_reads_its_settings_from_the_environment(tmp_path, monkeypatch):
    secret = tmp_path / "bao-token"
    secret.write_text("s.token\n")
    monkeypatch.setattr(plugins, "_bao_transport", lambda addr, tok, ns: FakeBao())
    p = plugins.load_key_provider("openbao", env={"CONSENTVAULT_OPENBAO_ADDR": "http://127.0.0.1:8200",
                                                  "CONSENTVAULT_OPENBAO_TOKEN_FILE": str(secret),
                                                  "CONSENTVAULT_OPENBAO_LEDGER": str(tmp_path / "ledger.json")})
    assert isinstance(p, OpenBaoKeyProvider) and p.provable_destruction is False


@pytest.mark.parametrize("drop", ["CONSENTVAULT_OPENBAO_ADDR", "CONSENTVAULT_OPENBAO_TOKEN_FILE",
                                  "CONSENTVAULT_OPENBAO_LEDGER"])
def test_openbao_missing_a_setting_is_named(tmp_path, drop):
    secret = tmp_path / "t"
    secret.write_text("s.token")
    env = {"CONSENTVAULT_OPENBAO_ADDR": "http://127.0.0.1:8200", "CONSENTVAULT_OPENBAO_TOKEN_FILE": str(secret),
           "CONSENTVAULT_OPENBAO_LEDGER": str(tmp_path / "l.json")}
    env.pop(drop)
    with pytest.raises(ConfigError, match=drop):
        plugins.load_key_provider("openbao", env=env)


def test_the_public_repository_carries_no_cloud_key_code():
    from pathlib import Path

    src = Path(plugins.__file__).resolve().parents[1]
    hits = [p for p in src.rglob("*.py") if "TrentService" in p.read_text(encoding="utf-8")]
    assert hits == []
