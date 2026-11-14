"""The four confirmation jobs (marketing/specs/confirmations-go-live): one CLI command per periodic pass of the service
(confirmations.md section 13), built from the job's own settings. A missing setting refuses by name; a pass that fails exits
non-zero so the job runner sends no heartbeat. No database here."""

from error_names import named  # noqa: F401

import pytest

from consentvault import cli, cmd_confirmations
from consentvault.confirm import wiring
from consentvault.config import load_config
from consentvault.errors import ConfigError

PASSES = {"confirmations-send": "run_sender", "confirmations-alarms": "run_alarm_checks",
          "confirmations-link-hosts": "recheck_link_hosts", "confirmations-purge": "purge"}


class FakeService:
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail

    def __getattr__(self, name):
        if name not in PASSES.values():
            raise AttributeError(name)

        def run(now=None):
            self.calls.append(name)
            if self.fail:
                raise self.fail
            return 0
        return run


def test_every_pass_has_its_command():
    for command in PASSES:
        assert command in cli.REGISTRY


@pytest.mark.parametrize("command,method", sorted(PASSES.items()))
def test_each_command_runs_its_one_pass(monkeypatch, command, method):
    svc = FakeService()
    monkeypatch.setattr(cmd_confirmations, "build_job_service", lambda cfg, env: svc)
    assert cli.main([command]) == 0 and svc.calls == [method]


@pytest.mark.parametrize("command", sorted(PASSES))
def test_a_failed_pass_exits_non_zero_with_the_class_name_only(monkeypatch, capsys, command):
    svc = FakeService(fail=RuntimeError("+15555550100 is a number that must never reach a log"))
    monkeypatch.setattr(cmd_confirmations, "build_job_service", lambda cfg, env: svc)
    assert cli.main([command]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "RuntimeError" in err and "5555550100" not in err


def test_the_jobs_refuse_without_the_confirmation_settings():
    env = {"CONSENTVAULT_DSN": "postgresql://x@127.0.0.1:1/x"}
    with pytest.raises(ConfigError, match=wiring.ENV_API_BASE):
        cmd_confirmations.build_job_service(load_config(env=env), env)


def test_the_jobs_refuse_half_configured_settings_by_name():
    env = {"CONSENTVAULT_DSN": "postgresql://x@127.0.0.1:1/x", wiring.ENV_API_BASE: "https://api.consentvault.ai"}
    with pytest.raises(ConfigError, match=wiring.ENV_EDGE_CNAME):
        cmd_confirmations.build_job_service(load_config(env=env), env)


def test_with_the_settings_the_job_goes_on_to_name_the_key_provider(monkeypatch):
    env = {"CONSENTVAULT_DSN": "postgresql://x@127.0.0.1:1/x", wiring.ENV_API_BASE: "https://api.consentvault.ai",
           wiring.ENV_EDGE_CNAME: "edge.consentvault.ai"}
    monkeypatch.delenv("CONSENTVAULT_KEY_PROVIDER", raising=False)
    with pytest.raises(ConfigError, match="key provider|CONSENTVAULT_KEY_PROVIDER"):
        cmd_confirmations.build_job_service(load_config(env=env), env)
