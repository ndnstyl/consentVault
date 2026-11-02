"""Every scheduled job but the alarm relay (which beats itself) sends one CloudWatch heartbeat after a clean run, in the
cloud only, into its own namespace (``ConsentVault/Heartbeat/<job>``, the only one its task role may write), carrying the
job name and nothing else. A failed run sends none; a heartbeat that cannot be sent fails the run by name (exit 2)."""

from error_names import named, named_any  # noqa: F401
import urllib.parse
from datetime import datetime, timedelta, timezone

import pytest

from consentvault import alarm_relay, cli, jobs
from consentvault.providers.rds_iam import AwsCredentials

BEATING = ("seal", "anchor", "verify-chain", "verify-seals", "erasure-resume", "usage-daily", "usage-retry",
           "replay-sweep", "erasure-commit-sweep", "records-exports", "key-lifecycle", "isolation-self-test", "restore-drill",
           "twenty-reconcile", "twenty-workflow-reminders")


class FakeAws:
    def get(self):
        return AwsCredentials("ASIAFAKE", "secret", "token", datetime.now(timezone.utc) + timedelta(hours=1))


class FakeMonitoring:
    def __init__(self, status=200):
        self.calls, self.status = [], status

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(urllib.parse.parse_qsl(body.decode()))))
        return self.status, {}, b"<PutMetricDataResponse/>" if self.status == 200 else b"<Error>AccessDenied</Error>"


@pytest.fixture
def cloud(monkeypatch):
    mon = FakeMonitoring()
    monkeypatch.setenv("CONSENTVAULT_DB_AUTH", "iam")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setattr(jobs, "_task_role_access", lambda env: FakeAws())
    monkeypatch.setattr(alarm_relay, "_urllib_transport", lambda **kw: mon)
    return mon


def test_the_heartbeat_jobs_are_every_built_scheduled_job_but_the_relay():
    assert set(jobs.HEARTBEAT_JOBS) == set(BEATING)
    assert all(jobs.JOBS[j] for j in BEATING) and "alarm-relay" not in jobs.HEARTBEAT_JOBS


@pytest.mark.parametrize("job", BEATING)
def test_a_clean_run_sends_one_heartbeat_into_the_jobs_own_namespace(monkeypatch, cloud, job):
    monkeypatch.setattr(cli, "main", lambda argv: 0)
    assert jobs.main([job]) == 0
    [(method, url, form)] = cloud.calls
    assert method == "POST" and url == "https://monitoring.us-east-1.amazonaws.com/"
    assert form == {"Action": "PutMetricData", "Version": "2010-08-01", "Namespace": f"ConsentVault/Heartbeat/{job}",
                    "MetricData.member.1.MetricName": "Heartbeat", "MetricData.member.1.Value": "1",
                    "MetricData.member.1.Unit": "Count", "MetricData.member.1.Dimensions.member.1.Name": "Job",
                    "MetricData.member.1.Dimensions.member.1.Value": job}


@pytest.mark.parametrize("job", BEATING)
def test_a_failed_run_sends_no_heartbeat_and_keeps_its_exit_code(monkeypatch, cloud, job):
    monkeypatch.setattr(cli, "main", lambda argv: 3)
    assert jobs.main([job]) == 3 and cloud.calls == []


def test_the_backfill_is_a_one_shot_and_never_beats(monkeypatch, cloud):
    monkeypatch.setattr(cli, "main", lambda argv: 0)
    assert jobs.main(["records-backfill"]) == 0 and cloud.calls == [] and "records-backfill" not in jobs.HEARTBEAT_JOBS


def test_the_relay_is_not_beaten_twice(monkeypatch, cloud):
    monkeypatch.setattr(cli, "main", lambda argv: 0)
    assert jobs.main(["alarm-relay"]) == 0 and cloud.calls == []


def test_the_self_host_sends_no_heartbeat(monkeypatch):
    monkeypatch.delenv("CONSENTVAULT_DB_AUTH", raising=False)
    monkeypatch.delenv("CV_DB_AUTH", raising=False)
    monkeypatch.setattr(jobs, "_task_role_access", lambda env: pytest.fail("the self-host reached for AWS access"))
    monkeypatch.setattr(cli, "main", lambda argv: 0)
    assert jobs.main(["seal"]) == 0


def test_a_heartbeat_that_cannot_be_sent_fails_the_run_by_name(monkeypatch, cloud, capsys):
    cloud.status = 403
    monkeypatch.setattr(cli, "main", lambda argv: 0)
    assert jobs.main(["verify-chain"]) == 2
    err = capsys.readouterr().err
    assert "verify-chain" in err and "heartbeat" in err and named_any(err) and "403" not in err


def test_the_cloud_without_a_region_fails_the_run_by_name(monkeypatch, cloud, capsys):
    monkeypatch.delenv("AWS_REGION")
    monkeypatch.setattr(cli, "main", lambda argv: 0)
    assert jobs.main(["seal"]) == 2
    assert "AWS_REGION" in capsys.readouterr().err
