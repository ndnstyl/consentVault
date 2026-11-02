"""End to end: the alarm-relay job drains the SES events queue as its own worker login, on a real database. A bounce becomes a
``bounced`` send-log row and a ``notify.bounce`` alarm on the alerts topic, then the queue message is deleted, then the
heartbeat. A row that cannot be written (here the database login is refused) leaves the message queued and fails the run
with no heartbeat."""

import json

from consentvault import alarm_relay, cli, cmd_alarms
from consentvault.notify import events as ev
from consentvault.notify.events import SqsQueue

from notify.test_mail_events import QUEUE, FakeSqs, bounce, complaint
from .test_alarm_relay import FakeAws, FakeSns, RecordingBeat, _cmd_env, _sink


def _queue(fake):
    return SqsQueue(QUEUE, "us-east-1", ev_creds(), transport=fake)


def ev_creds():
    from consentvault.providers.rds_iam import AwsCredentials

    class C:
        def get(self):
            return AwsCredentials("ASIARELAY", "relay-secret", "relay-session", None)
    return C()


def _rows(tenancy):
    with tenancy.superuser() as su:
        return [dict(r) for r in su.execute("SELECT type, recipient_domain, outcome, provider, provider_message_id, detail"
                                            " FROM consentvault.notify_send_log ORDER BY send_id")]


def test_the_relay_records_each_bounce_alarms_it_then_deletes_it_and_beats(tenancy, pg_server, monkeypatch, capsys):
    sns, sqs, beat = FakeSns(), FakeSqs([bounce(), complaint(to="lee@other.org")]), RecordingBeat()
    _cmd_env(tenancy, pg_server, monkeypatch, beat, _sink(sns))
    monkeypatch.setattr(cmd_alarms, "events_queue_for", lambda env, cloud: _queue(sqs))
    assert cli.main(["alarm-relay"]) == cli.EXIT_OK
    assert _rows(tenancy) == [
        {"type": "invite", "recipient_domain": "client.com", "outcome": "bounced", "provider": "ses",
         "provider_message_id": "0100-abc", "detail": "bounce Permanent General"},
        {"type": "security_alert", "recipient_domain": "other.org", "outcome": "bounced", "provider": "ses",
         "provider_message_id": "0100-def", "detail": "complaint abuse"}]
    alarms = [json.loads(form["Message"])["alarm"] for _, _, form in sns.calls]
    assert alarms == ["notify.bounce", "notify.complaint"]
    assert all("client.com" not in form["Message"] and "pat" not in form["Message"] for _, _, form in sns.calls)
    assert sqs.deleted == ["r0", "r1"] and beat.n == 1
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["mail_events"] == {"messages": 2, "bounces": 1, "complaints": 1, "unreadable": 0}


def test_a_send_log_row_that_cannot_be_written_keeps_the_event_and_fails_the_run_without_a_heartbeat(
        tenancy, pg_server, monkeypatch, capsys):
    sqs, beat = FakeSqs([bounce()]), RecordingBeat()
    _cmd_env(tenancy, pg_server, monkeypatch, beat, _sink(FakeSns()))
    monkeypatch.setattr(cmd_alarms, "events_queue_for", lambda env, cloud: _queue(sqs))
    monkeypatch.setattr(cmd_alarms, "_send_log_connect", lambda dsn: (_ for _ in ()).throw(
        __import__("psycopg").OperationalError("login refused")))
    assert cli.main(["alarm-relay"]) == cli.EXIT_ERROR
    assert sqs.deleted == [] and beat.n == 0
    assert "SendLogError" in capsys.readouterr().err


def test_an_alarm_that_cannot_be_published_keeps_the_event_and_fails_the_run(tenancy, pg_server, monkeypatch, capsys):
    sqs, beat = FakeSqs([bounce()]), RecordingBeat()
    _cmd_env(tenancy, pg_server, monkeypatch, beat, _sink(FakeSns(always_fail=True)))
    monkeypatch.setattr(cmd_alarms, "events_queue_for", lambda env, cloud: _queue(sqs))
    assert cli.main(["alarm-relay"]) == cli.EXIT_ERROR
    assert sqs.deleted == [] and beat.n == 0
    assert "EventsError" in capsys.readouterr().err


def test_the_cloud_relay_refuses_to_run_without_its_events_queue(monkeypatch):
    import pytest
    from consentvault.errors import ConfigError

    with pytest.raises(ConfigError, match=ev.ENV_QUEUE):
        cmd_alarms.events_queue_for({"AWS_REGION": "us-east-1"}, cloud=True)
    assert cmd_alarms.events_queue_for({}, cloud=False) is None
    assert FakeAws and alarm_relay  # the shared fakes stay importable


def test_a_retried_event_writes_one_bounce_row_in_the_database(tenancy, pg_server, monkeypatch, capsys):
    sqs, beat = FakeSqs([bounce()]), RecordingBeat()
    _cmd_env(tenancy, pg_server, monkeypatch, beat, _sink(FakeSns(always_fail=True)))
    monkeypatch.setattr(cmd_alarms, "events_queue_for", lambda env, cloud: _queue(sqs))
    assert cli.main(["alarm-relay"]) == cli.EXIT_ERROR and len(_rows(tenancy)) == 1
    sqs.queue = [{"MessageId": "m0", "ReceiptHandle": "r0b", "Body": json.dumps(bounce())}]
    monkeypatch.setattr(cmd_alarms, "alert_sink", lambda env, cloud: _sink(FakeSns()))
    assert cli.main(["alarm-relay"]) == cli.EXIT_OK
    assert len(_rows(tenancy)) == 1 and sqs.deleted == ["r0b"]
    with tenancy.superuser() as su:  # the database holds the rule, not only the writer
        import psycopg
        import pytest
        with pytest.raises(psycopg.errors.UniqueViolation):
            su.execute("INSERT INTO consentvault.notify_send_log (type, recipient_domain, outcome, provider,"
                       " provider_message_id, at) VALUES ('invite', 'client.com', 'bounced', 'ses', '0100-abc', now())")
