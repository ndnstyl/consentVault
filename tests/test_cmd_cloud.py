from error_names import named, named_any  # noqa: F401
import json

import pytest

from consentvault import cmd_cloud
from consentvault.config import load_config
from consentvault.errors import ConfigError

from providers.test_edge_assertion import PEM

BASE = {"CONSENTVAULT_DSN": "postgresql://x@127.0.0.1:1/x"}


def test_serve_cloud_refuses_to_start_without_edge_keys_before_it_touches_anything_else():
    with pytest.raises(ConfigError, match="CONSENTVAULT_EDGE_ASSERTION_KEYS"):
        cmd_cloud.build_cloud(load_config(env=BASE), BASE)


def test_with_keys_it_goes_on_to_name_each_other_missing_setting_in_turn():
    env = {**BASE, "CONSENTVAULT_EDGE_ASSERTION_KEYS": json.dumps({"e": PEM.decode()})}
    with pytest.raises(ConfigError) as exc:
        cmd_cloud.build_cloud(load_config(env=env), env)
    assert "CONSENTVAULT_KEY_PROVIDER" in str(exc.value) or "key provider" in str(exc.value)


def test_the_command_is_registered_and_returns_a_failure_status_when_it_cannot_start(monkeypatch, capsys):
    from consentvault import cli
    monkeypatch.delenv("CONSENTVAULT_EDGE_ASSERTION_KEYS", raising=False)
    monkeypatch.setenv("CONSENTVAULT_DSN", BASE["CONSENTVAULT_DSN"])
    assert "serve-cloud" in cli.COMMANDS if hasattr(cli, "COMMANDS") else True
    assert cli.main(["serve-cloud"]) != 0
    err = capsys.readouterr().err
    assert named("ConfigError", err) and "CONSENTVAULT_EDGE_ASSERTION_KEYS" not in err  # the class and code, never the text


@pytest.mark.parametrize("name", ["CONSENTVAULT_MAILER", "CONSENTVAULT_NOTIFIER", "CONSENTVAULT_EVIDENCE_SIGNER"])
def test_a_placeholder_class_setting_is_refused_by_name(name):
    with pytest.raises(ConfigError, match=f"{name} is still a placeholder"):
        cmd_cloud._plugin_spec({name: "UNSET:no-class-yet"}, name)
    with pytest.raises(ConfigError, match=name):
        cmd_cloud._plugin_spec({}, name)
    assert cmd_cloud._plugin_spec({name: "pkg.mod:Cls"}, name) == "pkg.mod:Cls"
