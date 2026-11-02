"""The cloud's product email: SES with the task role's access, the send log, and an alarm on the platform alerts topic.

``consentvault.notify.cloud`` builds the mailer (invitations) and the notifier (security alerts, delivery failures,
billing notices) from the task's settings and refuses to build either while a setting is missing or still a placeholder.
"""

import json
import urllib.parse
from datetime import datetime, timezone

import pytest

from consentvault.errors import ConfigError
from consentvault.notify import InMemorySendLog, Notifier, SendFailed
from consentvault.notify.cloud import (
    ENV_MAIL_FROM, ENV_PORTAL_URL, SesMailer, SesNotifier, SnsAlarm, mail_parts)
from consentvault.notify.errors import NotifyConfigError
from consentvault.notify.ses import HttpResponse, SesSender
from consentvault.providers.rds_iam import AwsCredentials

NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
TOPIC = "arn:aws:sns:us-east-1:845282034766:consentvault-alerts"
ENV = {
    "AWS_REGION": "us-east-1",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/x",
    "CONSENTVAULT_MAIL_FROM": "notices@consentvault.ai",
    "CONSENTVAULT_PORTAL_URL": "https://app.consentvault.ai",
    "CONSENTVAULT_ALERTS_TOPIC_ARN": TOPIC,
    "CONSENTVAULT_SES_CONFIGURATION_SET": "cv-mail",
    "CONSENTVAULT_DB_AUTH": "iam",
    "CONSENTVAULT_DB_HOST": "db.internal",
    "CONSENTVAULT_DB_NAME": "consentvault",
    "CONSENTVAULT_DB_USER": "consentvault_runtime",
}


class Creds:
    def __init__(self):
        self.calls = 0

    def get(self):
        self.calls += 1
        return AwsCredentials("ASIATASK", "task-secret", "task-session-token", None)


class Ses:
    def __init__(self, status=200, body=b'{"MessageId":"ses-1"}'):
        self.status, self.body, self.seen = status, body, []

    def __call__(self, req):
        self.seen.append(req)
        return HttpResponse(self.status, self.body)


class Sns:
    def __init__(self, status=200):
        self.status, self.seen = status, []

    def __call__(self, method, url, headers, body):
        self.seen.append((method, url, dict(headers), body))
        return self.status, {}, b"<PublishResponse/>"


def _sender(ses, creds=None):
    return SesSender(region="us-east-1", sender="notices@consentvault.ai", credentials=creds or Creds(), transport=ses,
                     clock=lambda: NOW)


def _alarm(sns, creds=None):
    from consentvault.alarm_relay import SnsTopic

    return SnsAlarm(SnsTopic(TOPIC, "us-east-1", creds or Creds(), transport=sns, clock=lambda: NOW))


# ---- SES with the task role's access ------------------------------------------------------------------------------------------
def test_ses_signs_with_the_task_roles_current_keys_and_session_token():
    ses, creds = Ses(), Creds()
    from consentvault.notify import Message

    assert _sender(ses, creds).send(Message("pat@client.com", "S", "T", "<p>H</p>")) == "ses-1"
    req = ses.seen[0]
    assert req.url == "https://email.us-east-1.amazonaws.com/v2/email/outbound-emails"
    assert req.headers["x-amz-security-token"] == "task-session-token"
    assert "Credential=ASIATASK/" in req.headers["Authorization"]
    assert json.loads(req.body)["FromEmailAddress"] == "notices@consentvault.ai"
    assert creds.calls == 1  # read for every send, so a rotated key is picked up


def test_ses_takes_static_keys_or_a_credential_source_never_both():
    with pytest.raises(NotifyConfigError):
        SesSender(region="us-east-1", sender="a@b.co", access_key="a", secret_key="b", credentials=Creds())
    with pytest.raises(NotifyConfigError):
        SesSender(region="us-east-1", sender="a@b.co")
    with pytest.raises(NotifyConfigError):
        SesSender(region="us-east-1", sender="a@b.co", credentials=object())


def test_task_role_keys_that_cannot_be_read_are_a_named_failed_send_that_is_logged_and_alarmed():
    from consentvault.providers.errors import ProviderTransportError

    class Down:
        def get(self):
            raise ProviderTransportError("credentials endpoint unreachable")

    sns, log = Sns(), InMemorySendLog()
    with pytest.raises(SendFailed, match="credentials_unavailable"):
        Notifier(_sender(Ses(), Down()), log, _alarm(sns)).send(
            "security_alert", "a@b.com", {"company": "Acme", "event": "x", "when": "now",
                                          "review_url": "https://app.consentvault.ai/settings"})
    assert log.records[0].outcome == "failed" and len(sns.seen) == 1


# ---- the mailer: invitations --------------------------------------------------------------------------------------------------
def test_an_invitation_carries_the_portal_accept_link_and_is_logged_by_domain_only():
    ses, log = Ses(), InMemorySendLog()
    mailer = SesMailer(Notifier(_sender(ses), log, _alarm(Sns())), portal_url="https://app.consentvault.ai")
    mailer.send_invite(to="pat@client.com", org_name="Acme Floors", role="admin", token="tok_abc-123",
                       expires_at=datetime(2026, 11, 7, 9, 30, tzinfo=timezone.utc), invited_by_name="Mike Soto")
    body = json.loads(ses.seen[0].body)
    assert body["Destination"] == {"ToAddresses": ["pat@client.com"]}
    content = body["Content"]["Simple"]
    assert "Acme Floors" in content["Subject"]["Data"]
    text = content["Body"]["Text"]["Data"]
    assert "https://app.consentvault.ai/invite?token=tok_abc-123" in text
    assert "2026-11-07 09:30 UTC" in text and "Mike Soto" in text
    rec = log.records[0]
    assert (rec.type, rec.recipient_domain, rec.outcome, rec.provider_message_id) == ("invite", "client.com", "sent", "ses-1")


def test_an_invitation_token_is_quoted_into_the_link():
    ses = Ses()
    mailer = SesMailer(Notifier(_sender(ses), InMemorySendLog(), _alarm(Sns())), portal_url="https://app.consentvault.ai")
    mailer.send_invite(to="pat@client.com", org_name="Acme", role="member", token="a b&c=d",
                       expires_at=NOW, invited_by_name="Lee")
    text = json.loads(ses.seen[0].body)["Content"]["Simple"]["Body"]["Text"]["Data"]
    assert "/invite?token=" + urllib.parse.quote("a b&c=d", safe="") in text


def test_a_refused_invitation_is_logged_alarmed_on_the_topic_without_the_address_and_raised():
    sns, log = Sns(), InMemorySendLog()
    mailer = SesMailer(Notifier(_sender(Ses(status=400, body=b'{"message":"pat@client.com bad"}')), log, _alarm(sns)),
                       portal_url="https://app.consentvault.ai")
    with pytest.raises(SendFailed):
        mailer.send_invite(to="pat@client.com", org_name="Acme", role="admin", token="t", expires_at=NOW,
                           invited_by_name="Lee")
    assert log.records[0].outcome == "failed"
    method, url, headers, body = sns.seen[0]
    form = urllib.parse.parse_qs(body.decode())
    assert url == "https://sns.us-east-1.amazonaws.com/" and form["TopicArn"] == [TOPIC]
    assert json.loads(form["Message"][0]) == {"alarm": "notify.send_failed", "source": "consentvault.notify"}
    assert "client.com" not in body.decode() and "pat" not in body.decode()


def test_an_alarm_that_cannot_reach_the_topic_is_logged_and_the_send_failure_still_raises(caplog):
    sns = Sns(status=500)
    n = Notifier(_sender(Ses(status=503)), InMemorySendLog(), _alarm(sns))
    with caplog.at_level("ERROR"), pytest.raises(SendFailed):
        n.send("security_alert", "a@b.com", {"company": "Acme", "event": "x", "when": "now",
                                             "review_url": "https://app.consentvault.ai/settings"})
    line = "\n".join(r.getMessage() for r in caplog.records)
    assert "the alarm could not be published to the alerts topic" in line
    assert "alarm=notify.send_failed" in line and "error=RelayPublishError" in line
    assert "b.com" not in line


# ---- built from the settings, refused while a setting is missing or a placeholder -------------------------------------------
def test_both_build_from_the_settings_without_calling_anything():
    mailer = SesMailer.from_environment(ENV)
    notifier = SesNotifier.from_environment(ENV)
    assert callable(mailer.send_invite)
    assert isinstance(notifier, Notifier) and callable(notifier.send)
    sender, _log, alarm, portal = mail_parts(ENV)
    assert sender.provider == "ses" and sender.sender == "notices@consentvault.ai" and sender.region == "us-east-1"
    assert isinstance(alarm, SnsAlarm) and portal == "https://app.consentvault.ai"


def test_the_classes_resolve_from_the_setting_values_the_task_definitions_carry():
    from consentvault.providers.plugins import resolve_object

    assert resolve_object("consentvault.notify.cloud:SesMailer") is SesMailer
    assert resolve_object("consentvault.notify.cloud:SesNotifier") is SesNotifier


@pytest.mark.parametrize("name", [ENV_MAIL_FROM, ENV_PORTAL_URL, "CONSENTVAULT_ALERTS_TOPIC_ARN", "AWS_REGION",
                                  "CONSENTVAULT_SES_CONFIGURATION_SET"])
@pytest.mark.parametrize("value", [None, "", "  ", "UNSET:not-chosen"])
def test_a_missing_or_placeholder_setting_refuses_both_by_name(name, value):
    env = dict(ENV)
    if value is None:
        env.pop(name)
    else:
        env[name] = value
    for cls in (SesMailer, SesNotifier):
        with pytest.raises(ConfigError, match=name):
            cls.from_environment(env)


def test_no_task_role_access_refuses_by_name():
    env = {k: v for k, v in ENV.items() if k != "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"}
    with pytest.raises(ConfigError, match="AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
        SesNotifier.from_environment(env)


@pytest.mark.parametrize("name,value", [
    (ENV_MAIL_FROM, "notices"),
    (ENV_MAIL_FROM, "Notices <notices@consentvault.ai>"),
    (ENV_MAIL_FROM, "a@b"),
    (ENV_PORTAL_URL, "http://app.consentvault.ai"),
    (ENV_PORTAL_URL, "https://app.consentvault.ai/path"),
    (ENV_PORTAL_URL, "https://app.consentvault.ai/?x=1"),
    (ENV_PORTAL_URL, "https://user@app.consentvault.ai"),
    ("CONSENTVAULT_ALERTS_TOPIC_ARN", "consentvault-alerts"),
    ("CONSENTVAULT_ALERTS_TOPIC_ARN", "arn:aws:sns:us-west-2:845282034766:consentvault-alerts"),
])
def test_a_malformed_setting_refuses_by_name(name, value):
    with pytest.raises(ConfigError, match=name):
        SesMailer.from_environment({**ENV, name: value})


def test_a_portal_url_with_a_trailing_slash_is_accepted_once():
    assert mail_parts({**ENV, ENV_PORTAL_URL: "https://app.consentvault.ai/"})[3] == "https://app.consentvault.ai"


# ---- opt-in live check against SES (never run by default) --------------------------------------------------------------------
@pytest.mark.skipif(not __import__("os").environ.get("CONSENTVAULT_LIVE_SES_TO"),
                    reason="live SES check: set CONSENTVAULT_LIVE_SES_TO, CONSENTVAULT_MAIL_FROM and AWS credentials")
def test_live_ses_sends_one_security_alert():  # pragma: no cover - needs AWS
    import os

    from consentvault.providers.rds_iam import AwsCredentials as C

    class Env:
        def get(self):
            return C(os.environ["AWS_ACCESS_KEY_ID"], os.environ["AWS_SECRET_ACCESS_KEY"],
                     os.environ.get("AWS_SESSION_TOKEN"), None)

    sender = SesSender(region=os.environ.get("AWS_REGION", "us-east-1"), sender=os.environ["CONSENTVAULT_MAIL_FROM"],
                       credentials=Env())
    log = InMemorySendLog()
    Notifier(sender, log, _alarm(Sns())).send(
        "security_alert", os.environ["CONSENTVAULT_LIVE_SES_TO"],
        {"company": "Live check", "event": "SES live check", "when": "now", "review_url": "https://app.consentvault.ai"})
    assert log.records[0].outcome == "sent"
