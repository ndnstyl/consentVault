"""Bounces and complaints for the cloud's product email.

SES publishes BOUNCE and COMPLAINT events for the configuration set the vault sends through to a private, encrypted SNS
topic; the topic delivers them (raw) to a private SQS queue; the alarm-relay job drains the queue every five minutes
(``consentvault.notify.events.drain``). Each recipient in an event becomes one ``bounced`` row in the send log (template
type from the send's ``cv_template`` tag, the recipient's domain, the SES message id, the bounce type) and one alarm on the
platform alerts topic; only then is the queue message deleted. SES's account-level suppression list keeps the address from
being sent to again. An event that cannot be read raises its own alarm and is deleted; a send-log row or an alarm that
cannot be written leaves the message on the queue and fails the run.

The contract records a stop only for an opt-out from a customer's text provider (confirmations.md, retries); our own
product email to a customer's admin records no stop, it is suppressed at SES.
"""

import json
from datetime import datetime, timezone

import pytest

from consentvault.errors import ConfigError
from consentvault.notify import InMemorySendLog, Message, Notifier
from consentvault.notify.errors import SendLogError
from consentvault.notify.events import (
    ALARM_COMPLAINT, ALARM_EVENT_UNREADABLE, EventsError, SqsQueue, drain, events_queue, parse_event)
from consentvault.notify.service import ALARM_BOUNCE
from consentvault.notify.ses import HttpResponse, SesSender
from consentvault.providers.rds_iam import AwsCredentials

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
QUEUE = "https://sqs.us-east-1.amazonaws.com/123456789012/cv-mail-events"


class Creds:
    def get(self):
        return AwsCredentials("ASIARELAY", "relay-secret", "relay-session", None)


def bounce(to="pat@client.com", template="invite", kind="Permanent", mid="0100-abc"):
    return {"eventType": "Bounce", "mail": {"messageId": mid, "tags": {"cv_template": [template]}, "destination": [to]},
            "bounce": {"bounceType": kind, "bounceSubType": "General", "bouncedRecipients": [{"emailAddress": to}]}}


def complaint(to="pat@client.com", template="security_alert", mid="0100-def"):
    return {"eventType": "Complaint", "mail": {"messageId": mid, "tags": {"cv_template": [template]}, "destination": [to]},
            "complaint": {"complaintFeedbackType": "abuse", "complainedRecipients": [{"emailAddress": to}]}}


class FakeSqs:
    """SQS's JSON protocol: ReceiveMessage hands out what is queued, DeleteMessage removes by receipt handle."""

    def __init__(self, bodies=(), status=200):
        self.queue = [{"MessageId": f"m{i}", "ReceiptHandle": f"r{i}", "Body": b if isinstance(b, str) else json.dumps(b)}
                      for i, b in enumerate(bodies)]
        self.status, self.requests, self.deleted = status, [], []

    def __call__(self, method, url, headers, body):
        self.requests.append((method, url, dict(headers), body))
        assert url == "https://sqs.us-east-1.amazonaws.com/" and headers["content-type"] == "application/x-amz-json-1.0"
        assert "Credential=ASIARELAY/" in headers["authorization"] and headers["x-amz-security-token"] == "relay-session"
        if self.status != 200:
            return self.status, {}, b'{"__type":"com.amazonaws.sqs#AccessDenied","message":"no"}'
        req, action = json.loads(body), headers["x-amz-target"]
        assert req["QueueUrl"] == QUEUE
        if action == "AmazonSQS.ReceiveMessage":
            batch, self.queue = self.queue[:req["MaxNumberOfMessages"]], self.queue[req["MaxNumberOfMessages"]:]
            return 200, {}, json.dumps({"Messages": batch} if batch else {}).encode()
        if action == "AmazonSQS.DeleteMessage":
            self.deleted.append(req["ReceiptHandle"])
            return 200, {}, b"{}"
        raise AssertionError(action)


class Alarms:
    def __init__(self, fail=False):
        self.rows, self.fail = [], fail

    def raise_alarm(self, name, detail):
        if self.fail:
            raise EventsError("alerts topic down", code="alarm_unpublished")
        self.rows.append((name, detail))


class Provider:
    provider = "ses"

    def send(self, message):  # pragma: no cover - the relay never sends
        raise AssertionError("the bounce recorder never sends")


def _queue(fake):
    return SqsQueue(QUEUE, "us-east-1", Creds(), transport=fake, clock=lambda: NOW)


def _drain(bodies, *, log=None, alarms=None, status=200):
    fake = FakeSqs(bodies, status=status)
    log, alarms = log or InMemorySendLog(), alarms or Alarms()
    out = drain(_queue(fake), Notifier(Provider(), log, alarms))
    return out, fake, log, alarms


# ---- end to end through the fakes ----------------------------------------------------------------------------------------------
def test_a_bounce_is_logged_by_domain_alarmed_and_only_then_deleted():
    out, fake, log, alarms = _drain([bounce()])
    assert out == {"bounces": 1, "complaints": 0, "unreadable": 0, "messages": 1}
    r = log.records[0]
    assert (r.type, r.recipient_domain, r.outcome, r.provider, r.provider_message_id) == (
        "invite", "client.com", "bounced", "ses", "0100-abc")
    assert r.detail == "bounce Permanent General"
    assert [a[0] for a in alarms.rows] == [ALARM_BOUNCE] and "pat@" not in alarms.rows[0][1]
    assert fake.deleted == ["r0"]


def test_a_complaint_is_logged_and_raises_its_own_alarm():
    out, fake, log, alarms = _drain([complaint()])
    assert out["complaints"] == 1 and log.records[0].type == "security_alert" and log.records[0].outcome == "bounced"
    assert log.records[0].detail == "complaint abuse"
    assert [a[0] for a in alarms.rows] == [ALARM_COMPLAINT] and fake.deleted == ["r0"]


def test_more_than_one_batch_is_drained_and_every_recipient_is_recorded():
    many = [bounce(to=f"a{i}@d{i}.com", mid=f"m-{i}") for i in range(23)]
    out, fake, log, _ = _drain(many)
    assert out["bounces"] == 23 and len(fake.deleted) == 23 and len(log.records) == 23
    assert {r.recipient_domain for r in log.records} == {f"d{i}.com" for i in range(23)}


def test_an_unreadable_event_raises_its_alarm_and_is_deleted_never_retried_forever():
    out, fake, log, alarms = _drain(["not json", {"eventType": "Bounce", "mail": {"messageId": "x"}},
                                     bounce(template="newsletter"), {"eventType": "Delivery", "mail": {}}])
    assert out == {"bounces": 0, "complaints": 0, "unreadable": 4, "messages": 4}
    assert [a[0] for a in alarms.rows] == [ALARM_EVENT_UNREADABLE] * 4 and log.records == []
    assert fake.deleted == ["r0", "r1", "r2", "r3"]


def test_a_send_log_that_cannot_be_written_keeps_the_message_and_fails_the_run():
    class DownLog:
        def append(self, record):
            raise SendLogError("db down")

    fake = FakeSqs([bounce()])
    with pytest.raises(SendLogError):
        drain(_queue(fake), Notifier(Provider(), DownLog(), Alarms()))
    assert fake.deleted == []


def test_an_alarm_that_cannot_be_published_keeps_the_message_and_fails_the_run():
    fake = FakeSqs([bounce()])
    with pytest.raises(EventsError):
        drain(_queue(fake), Notifier(Provider(), InMemorySendLog(), Alarms(fail=True)))
    assert fake.deleted == []


def test_a_queue_that_refuses_is_a_named_error():
    with pytest.raises(EventsError) as e:
        _drain([bounce()], status=403)
    assert e.value.code == "sqs_refused"


def test_parse_reads_only_what_the_log_needs():
    assert parse_event(json.dumps(bounce())) == [("bounce", "invite", "pat@client.com", "0100-abc", "bounce Permanent General")]


# ---- the sender tags each message with its template so a bounce can name it ---------------------------------------------------
def test_ses_sends_through_the_configuration_set_with_the_template_tag():
    seen = []
    s = SesSender(region="us-east-1", sender="no-reply@consentvault.ai", credentials=Creds(), configuration_set="cv-mail",
                  transport=lambda req: seen.append(req) or HttpResponse(200, b'{"MessageId":"m"}'), clock=lambda: NOW)
    Notifier(s, InMemorySendLog(), Alarms()).send("invite", "pat@client.com", {
        "company": "Acme", "inviter_name": "Lee", "accept_url": "https://app.consentvault.ai/invite?token=t", "expires_at": "x"})
    body = json.loads(seen[0].body)
    assert body["ConfigurationSetName"] == "cv-mail"
    assert body["EmailTags"] == [{"Name": "cv_template", "Value": "invite"}]


def test_a_message_without_a_template_carries_no_tag():
    seen = []
    s = SesSender(region="us-east-1", sender="no-reply@consentvault.ai", credentials=Creds(),
                  transport=lambda req: seen.append(req) or HttpResponse(200, b'{"MessageId":"m"}'), clock=lambda: NOW)
    s.send(Message("a@b.com", "S", "T", "<p>H</p>"))
    assert "EmailTags" not in json.loads(seen[0].body) and "ConfigurationSetName" not in json.loads(seen[0].body)


# ---- the relay's settings ------------------------------------------------------------------------------------------------------
ENV = {"AWS_REGION": "us-east-1", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/x",
       "CONSENTVAULT_SES_EVENTS_QUEUE_URL": QUEUE}


def test_the_cloud_relay_needs_the_events_queue_and_the_self_host_has_none():
    assert isinstance(events_queue(ENV, cloud=True), SqsQueue)
    assert events_queue({}, cloud=False) is None
    for env in ({**ENV, "CONSENTVAULT_SES_EVENTS_QUEUE_URL": ""}, {**ENV, "CONSENTVAULT_SES_EVENTS_QUEUE_URL": "UNSET:x"},
                {k: v for k, v in ENV.items() if k != "CONSENTVAULT_SES_EVENTS_QUEUE_URL"}):
        with pytest.raises(ConfigError, match="CONSENTVAULT_SES_EVENTS_QUEUE_URL"):
            events_queue(env, cloud=True)


@pytest.mark.parametrize("url", ["http://sqs.us-east-1.amazonaws.com/123456789012/q", "https://evil.example.com/123456789012/q",
                                 "https://sqs.us-west-2.amazonaws.com/123456789012/q", "https://sqs.us-east-1.amazonaws.com/q"])
def test_a_queue_url_outside_this_region_or_not_sqs_is_refused(url):
    with pytest.raises(ConfigError, match="CONSENTVAULT_SES_EVENTS_QUEUE_URL"):
        events_queue({**ENV, "CONSENTVAULT_SES_EVENTS_QUEUE_URL": url}, cloud=True)


def test_the_cloud_mailer_needs_its_configuration_set():
    from consentvault.notify.cloud import SesNotifier

    env = {"AWS_REGION": "us-east-1", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/x", "CONSENTVAULT_MAIL_FROM": "no-reply@consentvault.ai",
           "CONSENTVAULT_PORTAL_URL": "https://app.consentvault.ai",
           "CONSENTVAULT_ALERTS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:cv-alerts", "CONSENTVAULT_DB_AUTH": "iam",
           "CONSENTVAULT_DB_HOST": "h", "CONSENTVAULT_DB_NAME": "n", "CONSENTVAULT_DB_USER": "u"}
    with pytest.raises(ConfigError, match="CONSENTVAULT_SES_CONFIGURATION_SET"):
        SesNotifier.from_environment(env)
    n = SesNotifier.from_environment({**env, "CONSENTVAULT_SES_CONFIGURATION_SET": "cv-mail"})
    assert n._sender.configuration_set == "cv-mail"


def test_the_queue_is_reached_only_through_the_shared_opener_with_the_exact_sqs_host(monkeypatch):
    from consentvault import urlguard

    seen = {}

    def stub(req, **kw):
        seen.update(kw)
        raise TimeoutError("deadline")

    monkeypatch.setattr(urlguard, "open_no_redirect", stub)
    from consentvault.notify import events

    with pytest.raises(EventsError) as e:
        events._urllib_transport()("POST", "https://sqs.us-east-1.amazonaws.com/", {}, b"{}")
    assert e.value.code == "sqs_unreachable"
    assert seen == {"timeout": events.TIMEOUT_S, "host_pattern": events.SQS_HOST_PATTERN, "loopback_http": False}
    monkeypatch.undo()
    with pytest.raises(urlguard.UrlRefusedError):
        events._urllib_transport()("POST", "https://sqs.us-east-1.amazonaws.com.evil.example/", {}, b"{}")


def test_a_retry_after_a_failed_alarm_writes_no_second_row_and_still_alarms():
    fake, log = FakeSqs([bounce()]), InMemorySendLog()
    with pytest.raises(EventsError):
        drain(_queue(fake), Notifier(Provider(), log, Alarms(fail=True)))
    assert len(log.records) == 1 and fake.deleted == []
    fake.queue = [{"MessageId": "m0", "ReceiptHandle": "r0b", "Body": json.dumps(bounce())}]  # redelivered
    alarms = Alarms()
    drain(_queue(fake), Notifier(Provider(), log, alarms))
    assert len(log.records) == 1 and [a[0] for a in alarms.rows] == [ALARM_BOUNCE] and fake.deleted == ["r0b"]


def test_the_in_memory_log_keeps_one_bounce_row_per_provider_message_id():
    from consentvault.notify import SendRecord

    log = InMemorySendLog()
    for _ in range(2):
        log.append(SendRecord("invite", "client.com", "bounced", "ses", "m-1", "bounce Permanent"))
    log.append(SendRecord("invite", "client.com", "sent", "ses", "m-1"))
    assert [r.outcome for r in log.records] == ["bounced", "sent"]
