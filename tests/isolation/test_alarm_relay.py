"""The alarm relay: operator alarms are published to the alerts channel and marked relayed only after the publish
succeeded; retried with backoff; named and failing when they cannot be published; an alarm that waited past 15 minutes is
its own failure; the message carries kind, organisation, counts and times and nothing else."""

import json
import urllib.parse
import uuid

import pytest

from consentvault import alarm_relay, cli, cmd_alarms, db
from consentvault.alarms import raise_operator_alarm
from consentvault.errors import ConfigError
from consentvault.providers.rds_iam import AwsCredentials
from consentvault.tenancy.tokens import org_transaction

from .harness import make_login_role

TOPIC = "arn:aws:sns:us-east-1:123456789012:cv-alerts"
SECRET_REF, SECRET_REQ = uuid.UUID("11111111-2222-4333-8444-555555555555"), "req-private-0001"


class FakeAws:
    def get(self):
        from datetime import datetime, timedelta, timezone

        return AwsCredentials("ASIAFAKE", "secret", "token", datetime.now(timezone.utc) + timedelta(hours=1))


class FakeSns:
    def __init__(self, fail_first=0, always_fail=False, probe=None):
        self.calls, self.fail_first, self.always_fail, self.probe = [], fail_first, always_fail, probe

    def __call__(self, method, url, headers, body):
        form = dict(urllib.parse.parse_qsl(body.decode()))
        if self.probe:
            self.probe(form)
        self.calls.append((url, headers, form))
        if self.always_fail or len(self.calls) <= self.fail_first:
            return 500, {}, b"<Error>InternalFailure</Error>"
        return 200, {}, b"<PublishResponse/>"


def _raise(tenancy, org, name="restore.stops_unconfirmed"):
    with tenancy.app() as app, org_transaction(app, tenancy.token(org)):
        raise_operator_alarm(app, name=name, error_class="UnconfirmedErasureStop", ref_kind="erasure", ref_id=SECRET_REF,
                             request_id=SECRET_REQ)


def _worker(tenancy, pg_server):
    return db.connect(make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_worker"))


def _relayed(tenancy):
    with tenancy.superuser() as su:
        return [r["relayed_at"] is not None for r in su.execute(
            "SELECT relayed_at FROM consentvault.operator_alarm ORDER BY raised_at")]


def _sink(sns):
    return alarm_relay.SnsTopic(TOPIC, "us-east-1", FakeAws(), transport=sns)


def test_a_pending_alarm_is_published_signed_to_the_topic_and_then_marked(tenancy, pg_server):
    _raise(tenancy, tenancy.a)
    sns = FakeSns()
    with _worker(tenancy, pg_server) as w:
        out = alarm_relay.relay_once(w, _sink(sns), sleep=lambda s: None)
    assert out == {"relayed": 1, "failed": [], "stale": [], "skipped": 0, "already_running": False}
    url, headers, form = sns.calls[0]
    assert url == "https://sns.us-east-1.amazonaws.com/" and form["Action"] == "Publish" and form["TopicArn"] == TOPIC
    assert headers["authorization"].startswith("AWS4-HMAC-SHA256 Credential=ASIAFAKE/") and "/sns/aws4_request" in headers["authorization"]
    assert _relayed(tenancy) == [True]
    with _worker(tenancy, pg_server) as w:  # relayed once: nothing is published twice
        assert alarm_relay.relay_once(w, _sink(sns), sleep=lambda s: None)["relayed"] == 0
    assert len(sns.calls) == 1


def test_the_message_is_kind_organisation_counts_and_times_only(tenancy, pg_server):
    _raise(tenancy, tenancy.a)
    _raise(tenancy, tenancy.a, name="lifecycle.ledger_commit_overdue")
    sns = FakeSns()
    with _worker(tenancy, pg_server) as w:
        alarm_relay.relay_once(w, _sink(sns), sleep=lambda s: None)
    for _, _, form in sns.calls:
        msg = json.loads(form["Message"])
        assert set(msg) == {"alarm", "error_class", "ref_kind", "org_id", "alarm_id", "raised_at", "unrelayed_in_org"}
        assert msg["org_id"] == str(tenancy.a.org_id) and msg["unrelayed_in_org"] == 2
        everything = json.dumps(form)
        assert str(SECRET_REF) not in everything and SECRET_REQ not in everything


def test_a_failed_publish_is_retried_with_backoff_then_succeeds(tenancy, pg_server):
    _raise(tenancy, tenancy.a)
    sns, sleeps = FakeSns(fail_first=2), []
    with _worker(tenancy, pg_server) as w:
        out = alarm_relay.relay_once(w, _sink(sns), sleep=sleeps.append)
    assert out["relayed"] == 1 and len(sns.calls) == 3 and sleeps == [1.0, 2.0]
    assert _relayed(tenancy) == [True]


def test_an_alarm_is_never_marked_before_its_publish_succeeds(tenancy, pg_server):
    _raise(tenancy, tenancy.a)
    seen = []

    def probe(form):  # at the moment of each publish attempt the alarm must still be unmarked
        seen.append(_relayed(tenancy))

    with _worker(tenancy, pg_server) as w:
        alarm_relay.relay_once(w, _sink(FakeSns(fail_first=1, probe=probe)), sleep=lambda s: None)
    assert seen == [[False], [False]] and _relayed(tenancy) == [True]
    _raise(tenancy, tenancy.b)
    with _worker(tenancy, pg_server) as w:
        out = alarm_relay.relay_once(w, _sink(FakeSns(always_fail=True)), sleep=lambda s: None)
    assert out["relayed"] == 0 and len(out["failed"]) == 1 and out["failed"][0]["attempts"] == 4
    assert out["failed"][0]["error"] == "RelayPublishError (code publish_retries_spent)"
    assert _relayed(tenancy) == [True, False]  # the failed one stays unrelayed for the next run


def test_the_command_exits_2_naming_the_alarm_it_could_not_publish_and_the_log_sink_works_in_self_host(
        tenancy, pg_server, monkeypatch, capsys, tmp_path):
    _raise(tenancy, tenancy.a)
    dsn = make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_worker")
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)
    monkeypatch.setenv("CONSENTVAULT_ALERTS_LOG", str(tmp_path / "no-such-dir" / "alerts.log"))
    cli.build_parser()
    monkeypatch.setattr(alarm_relay, "RETRY_DELAYS_S", (0.0, 0.0, 0.0))
    assert cli.main(["alarm-relay"]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "restore.stops_unconfirmed" in err and "could not publish" in err
    log = tmp_path / "alerts.log"
    monkeypatch.setenv("CONSENTVAULT_ALERTS_LOG", str(log))
    assert cli.main(["alarm-relay"]) == cli.EXIT_OK
    lines = log.read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["alarm"] == "restore.stops_unconfirmed"
    assert cli.main(["alarm-relay"]) == cli.EXIT_OK and len(log.read_text().splitlines()) == 1  # nothing twice


def test_an_alarm_unrelayed_past_fifteen_minutes_is_a_heartbeat_failure_even_though_it_is_relayed_now(
        tenancy, pg_server, monkeypatch, capsys, tmp_path):
    with tenancy.superuser() as su:
        su.execute("INSERT INTO consentvault.operator_alarm (org_id, name, error_class, raised_at)"
                   " VALUES (%s, 'lifecycle.ledger_commit_pending', 'LedgerUnavailableError', now() - interval '20 minutes')",
                   (tenancy.a.org_id,))
    monkeypatch.setenv("CONSENTVAULT_DSN", make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1],
                                                           "consentvault_worker"))
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)
    monkeypatch.setenv("CONSENTVAULT_ALERTS_LOG", str(tmp_path / "alerts.log"))
    cli.build_parser()
    assert cli.main(["alarm-relay"]) == cli.EXIT_BROKEN
    assert "heartbeat failure" in capsys.readouterr().err and _relayed(tenancy) == [True]
    _raise(tenancy, tenancy.a)  # a young alarm is not a heartbeat failure
    assert cli.main(["alarm-relay"]) == cli.EXIT_OK


def test_the_relay_login_reads_and_marks_through_the_two_functions_only(tenancy, pg_server):
    import psycopg

    _raise(tenancy, tenancy.a)
    with _worker(tenancy, pg_server) as w:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            w.execute("SELECT * FROM consentvault.operator_alarm")
    with _worker(tenancy, pg_server) as w:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            w.execute("UPDATE consentvault.operator_alarm SET relayed_at = now()")
    with tenancy.superuser() as su:  # and a relayed mark can be set once, an alarm's other columns never change
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            su.execute("UPDATE consentvault.operator_alarm SET name = 'other.name'")
        su.execute("UPDATE consentvault.operator_alarm SET relayed_at = now()")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            su.execute("UPDATE consentvault.operator_alarm SET relayed_at = now() + interval '1 minute'")


def test_the_cloud_needs_the_topic_and_refuses_a_log_file(tmp_path):
    with pytest.raises(ConfigError, match="CONSENTVAULT_ALERTS_LOG.*local.*cloud"):
        cmd_alarms.alert_sink({"CONSENTVAULT_ALERTS_LOG": str(tmp_path / "a")}, cloud=True)
    with pytest.raises(ConfigError, match="CONSENTVAULT_ALERTS_TOPIC_ARN"):
        cmd_alarms.alert_sink({}, cloud=True)
    sink = cmd_alarms.alert_sink({"CONSENTVAULT_ALERTS_TOPIC_ARN": TOPIC, "AWS_REGION": "us-east-1",
                                  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/x"}, cloud=True)
    assert isinstance(sink, alarm_relay.SnsTopic)


def test_the_job_is_registered(monkeypatch):
    from consentvault import jobs

    seen = []
    monkeypatch.setattr(cli, "main", lambda argv: seen.append(list(argv)) or 0)
    assert jobs.main(["alarm-relay"]) == 0 and seen == [["alarm-relay"]]


def test_the_relay_reaches_sns_only_through_the_shared_opener_with_an_exact_host_and_a_deadline(monkeypatch):
    import urllib.error

    from consentvault import alarm_relay as ar

    seen = {}

    class Redirect(Exception):
        pass

    def stub(req, **kw):
        seen.update(kw)
        raise urllib.error.HTTPError(req.full_url, 302, "Found", {"Location": "https://evil.example/"}, None)

    monkeypatch.setattr(ar, "open_no_redirect", stub)
    status, _, _ = ar._urllib_transport()("POST", "https://sns.us-east-1.amazonaws.com/", {}, b"x")
    assert status == 302  # a redirect is an answer, never followed; publish() refuses it
    assert seen == {"timeout": 10.0, "host_pattern": ar.SNS_HOST_PATTERN, "loopback_http": False}
    with pytest.raises(ar.RelayPublishError, match="HTTP 302"):
        ar.SnsTopic(TOPIC, "us-east-1", FakeAws(), transport=ar._urllib_transport()).publish("s", "m")

    def slow(req, **kw):
        raise TimeoutError("the call passed its 10.0s deadline")

    monkeypatch.setattr(ar, "open_no_redirect", slow)
    with pytest.raises(ar.RelayPublishError, match="could not be reached: TimeoutError"):
        ar._urllib_transport()("POST", "https://sns.us-east-1.amazonaws.com/", {}, b"x")


def test_a_host_that_is_not_an_exact_sns_host_is_refused_before_anything_is_sent():
    from consentvault import alarm_relay as ar, urlguard

    for url in ("https://sns.us-east-1.amazonaws.com.evil.example/", "https://evil.example/", "http://sns.us-east-1.amazonaws.com/",
                "https://sns.us-east-1.amazonaws.com@evil.example/"):
        with pytest.raises(urlguard.UrlRefusedError):
            ar._urllib_transport()("POST", url, {}, b"x")


def test_an_overlapping_run_publishes_nothing_and_answers_already_running(tenancy, pg_server):
    _raise(tenancy, tenancy.a)
    second = []

    def probe(form):  # while the first run is publishing, a second run starts
        if not second:
            with _worker(tenancy, pg_server) as w2:
                second.append(alarm_relay.relay_once(w2, _sink(inner), sleep=lambda s: None))

    inner = FakeSns()
    outer = FakeSns(probe=probe)
    with _worker(tenancy, pg_server) as w:
        out = alarm_relay.relay_once(w, _sink(outer), sleep=lambda s: None)
    assert out["relayed"] == 1 and out["failed"] == [] and not out.get("already_running")
    assert second == [{"relayed": 0, "failed": [], "stale": [], "skipped": 0, "already_running": True}]
    assert inner.calls == [] and len(outer.calls) == 1 and _relayed(tenancy) == [True]
    with _worker(tenancy, pg_server) as w:  # the lock is released when the run ends
        assert alarm_relay.relay_once(w, _sink(FakeSns()), sleep=lambda s: None)["already_running"] is False


def test_the_command_exits_0_with_a_named_line_when_another_run_holds_the_lock(tenancy, pg_server, monkeypatch, capsys,
                                                                                tmp_path):
    _raise(tenancy, tenancy.a)
    monkeypatch.setenv("CONSENTVAULT_DSN", make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1],
                                                           "consentvault_worker"))
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)
    log = tmp_path / "alerts.log"
    monkeypatch.setenv("CONSENTVAULT_ALERTS_LOG", str(log))
    cli.build_parser()
    with _worker(tenancy, pg_server) as holder:
        assert holder.execute(alarm_relay.RELAY_LOCK_SQL).fetchone()["got"] is True
        assert cli.main(["alarm-relay"]) == cli.EXIT_OK
    assert "alarm-relay already running" in capsys.readouterr().err
    assert not log.exists() and _relayed(tenancy) == [False]


def test_the_batch_stops_after_the_first_publish_that_exhausts_its_retries(tenancy, pg_server):
    for _ in range(3):
        _raise(tenancy, tenancy.a)
    sns = FakeSns(always_fail=True)
    with _worker(tenancy, pg_server) as w:
        out = alarm_relay.relay_once(w, _sink(sns), sleep=lambda s: None)
    assert len(sns.calls) == 1 + len(alarm_relay.RETRY_DELAYS_S)  # one alarm's attempts, then the batch stops
    assert out["relayed"] == 0 and len(out["failed"]) == 1 and out["skipped"] == 2
    assert _relayed(tenancy) == [False, False, False]


class FakeMonitoring:
    def __init__(self, status=200):
        self.calls, self.status = [], status

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, dict(urllib.parse.parse_qsl(body.decode()))))
        return self.status, {}, b"<PutMetricDataResponse/>" if self.status == 200 else b"<Error>Throttling</Error>"


def test_the_heartbeat_is_one_signed_metric_with_the_job_name_and_nothing_else():
    mon = FakeMonitoring()
    alarm_relay.CloudWatchHeartbeat("us-east-1", FakeAws(), transport=mon).beat()
    [(method, url, headers, form)] = mon.calls
    assert method == "POST" and url == "https://monitoring.us-east-1.amazonaws.com/"
    assert form == {"Action": "PutMetricData", "Version": "2010-08-01", "Namespace": "ConsentVault/Heartbeat/alarm-relay",
                    "MetricData.member.1.MetricName": "Heartbeat", "MetricData.member.1.Value": "1",
                    "MetricData.member.1.Unit": "Count", "MetricData.member.1.Dimensions.member.1.Name": "Job",
                    "MetricData.member.1.Dimensions.member.1.Value": "alarm-relay"}
    assert "/us-east-1/monitoring/aws4_request" in headers["authorization"]
    with pytest.raises(alarm_relay.RelayPublishError, match="HTTP 400 to the heartbeat"):
        alarm_relay.CloudWatchHeartbeat("us-east-1", FakeAws(), transport=FakeMonitoring(400)).beat()


def test_the_heartbeat_reaches_cloudwatch_only_through_the_shared_opener_with_an_exact_host(monkeypatch):
    from consentvault import alarm_relay as ar, urlguard

    seen = {}

    def stub(req, **kw):
        seen.update(kw)
        raise TimeoutError("deadline")

    monkeypatch.setattr(ar, "open_no_redirect", stub)
    with pytest.raises(ar.RelayPublishError, match="could not be reached"):
        ar.CloudWatchHeartbeat("us-east-1", FakeAws()).beat()
    assert seen == {"timeout": 10.0, "host_pattern": ar.MONITORING_HOST_PATTERN, "loopback_http": False}
    monkeypatch.undo()
    for url in ("https://sns.us-east-1.amazonaws.com/", "https://monitoring.us-east-1.amazonaws.com.evil.example/"):
        with pytest.raises(urlguard.UrlRefusedError):
            ar._urllib_transport(host_pattern=ar.MONITORING_HOST_PATTERN)("POST", url, {}, b"x")


class RecordingBeat:
    def __init__(self, fail=False):
        self.n, self.fail = 0, fail

    def beat(self):
        self.n += 1
        if self.fail:
            raise alarm_relay.RelayPublishError("CloudWatch answered HTTP 500 to the heartbeat")


def _cmd_env(tenancy, pg_server, monkeypatch, beat, sink):
    monkeypatch.setenv("CONSENTVAULT_DSN", make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1],
                                                           "consentvault_worker"))
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)
    monkeypatch.setattr(cmd_alarms, "alert_sink", lambda env, cloud: sink)
    monkeypatch.setattr(cmd_alarms, "heartbeat_for", lambda env: beat)
    monkeypatch.setattr(alarm_relay, "RETRY_DELAYS_S", (0.0, 0.0, 0.0))
    cli.build_parser()


def test_a_successful_run_sends_one_heartbeat_and_a_failed_one_sends_none(tenancy, pg_server, monkeypatch, capsys):
    beat = RecordingBeat()
    _cmd_env(tenancy, pg_server, monkeypatch, beat, _sink(FakeSns()))
    assert cli.main(["alarm-relay"]) == cli.EXIT_OK and beat.n == 1  # a run with nothing to relay still beats
    _raise(tenancy, tenancy.a)
    assert cli.main(["alarm-relay"]) == cli.EXIT_OK and beat.n == 2
    _raise(tenancy, tenancy.b)
    _cmd_env(tenancy, pg_server, monkeypatch, beat, _sink(FakeSns(always_fail=True)))
    assert cli.main(["alarm-relay"]) == cli.EXIT_ERROR and beat.n == 2


def test_a_heartbeat_that_cannot_be_sent_fails_the_run_by_name(tenancy, pg_server, monkeypatch, capsys):
    _cmd_env(tenancy, pg_server, monkeypatch, RecordingBeat(fail=True), _sink(FakeSns()))
    assert cli.main(["alarm-relay"]) == cli.EXIT_ERROR
    assert "heartbeat could not be sent" in capsys.readouterr().err


def test_the_cloud_sends_heartbeats_and_the_self_host_does_not():
    env = {"CONSENTVAULT_ALERTS_TOPIC_ARN": TOPIC, "AWS_REGION": "us-east-1"}
    assert isinstance(cmd_alarms.heartbeat_for(env), alarm_relay.CloudWatchHeartbeat)
    assert cmd_alarms.heartbeat_for({"CONSENTVAULT_ALERTS_LOG": "/tmp/x.log"}) is None
