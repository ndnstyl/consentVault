"""The commands the cloud schedules and services run exist in the product:
``python -m consentvault.jobs <job>`` for every scheduled job, and ``python -m consentvault.sync`` for the sync worker.
A job the product does not have yet is refused by name (exit 2), never a silent success."""

import subprocess
import sys

import pytest

from consentvault import cli, jobs

SCHEDULED = ("seal", "anchor", "verify-chain", "verify-seals", "isolation-self-test", "key-lifecycle", "erasure-resume",
             "replay-sweep", "erasure-commit-sweep", "alarm-relay", "usage-daily", "usage-retry", "usage-acknowledge", "restore-drill", "records-exports", "records-backfill",
             "twenty-reconcile", "twenty-workflow-reminders", "projection-rebuild", "confirmations-send", "confirmations-alarms", "confirmations-link-hosts", "confirmations-purge")


def test_every_scheduled_job_name_is_known():
    assert set(SCHEDULED) == set(jobs.JOBS)


@pytest.mark.parametrize("job,command", [("seal", "seal"), ("anchor", "anchor"), ("verify-chain", "verify-chain"),
                                         ("verify-seals", "verify-seals"), ("erasure-resume", "erasure-resume"),
                                         ("replay-sweep", "replay-sweep"),
                                         ("erasure-commit-sweep", "erasure-commit-sweep"),
                                         ("records-exports", "records-exports"),
                                         ("records-backfill", "records-backfill"),
                                         ("key-lifecycle", "key-lifecycle"),
                                         ("isolation-self-test", "isolation-self-test"),
                                         ("restore-drill", "restore-drill"),
                                         ("twenty-reconcile", "twenty-reconcile"),
                                         ("twenty-workflow-reminders", "twenty-workflow-reminders"),
                                         ("projection-rebuild", "projection-rebuild"),
                                         ("confirmations-send", "confirmations-send"),
                                         ("confirmations-alarms", "confirmations-alarms"),
                                         ("confirmations-link-hosts", "confirmations-link-hosts"),
                                         ("confirmations-purge", "confirmations-purge")])
def test_a_built_job_runs_its_cli_command(monkeypatch, job, command):
    seen = []
    monkeypatch.setattr(cli, "main", lambda argv: seen.append(list(argv)) or 0)
    assert jobs.main([job]) == 0 and seen == [[command]]


def test_a_job_not_built_yet_is_refused_by_name(monkeypatch, capsys):
    monkeypatch.setitem(jobs.JOBS, "not-built-job", None)
    monkeypatch.setattr(cli, "main", lambda argv: pytest.fail("ran a command for a job that does not exist"))
    assert jobs.main(["not-built-job"]) == 2
    assert "not-built-job" in capsys.readouterr().err


def test_every_registered_job_is_built():
    assert all(jobs.JOBS.values()), [j for j, c in jobs.JOBS.items() if c is None]


def test_an_unknown_job_or_none_is_refused(capsys):
    assert jobs.main(["no-such-job"]) == 2 and jobs.main([]) == 2


def test_the_modules_run_as_scripts():
    for module, args in (("consentvault.jobs", ["no-such-job"]), ("consentvault.sync", ["--help"])):
        res = subprocess.run([sys.executable, "-m", module, *args], capture_output=True, text=True, timeout=60)  # loud-failure-exempt: the exit code is asserted below
        assert res.returncode in (0, 2), (module, res.stderr)
    help_text = subprocess.run([sys.executable, "-m", "consentvault.sync", "--help"], capture_output=True, text=True,
                               timeout=60, check=True).stdout
    assert "--once" in help_text
