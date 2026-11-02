import json
import smtplib
from datetime import datetime, timezone

import pytest

from consentvault.notify import (
    ALARM_BOUNCE, ALARM_SEND_FAILED, InMemorySendLog, Message, NotifyConfigError, NotifyRefused,
    Notifier, SendFailed, SesSender, SmtpSender, render,
)
from consentvault.notify.ses import HttpResponse

GOOD = {
    "invite": {"company": "Acme Floors", "inviter_name": "Dana", "accept_url": "https://consentvault.ai/i/abc",
               "expires_at": "5 Nov 2026 14:00 UTC"},
    "security_alert": {"company": "Acme Floors", "event": "a new API key was created", "when": "29 Oct 2026 10:00 UTC",
                       "review_url": "https://consentvault.ai/security"},
    "delivery_failure": {"company": "Acme Floors", "failed_count": "12", "period": "day",
                         "details_url": "https://consentvault.ai/deliveries"},
    "billing_notice": {"company": "Acme Floors", "notice": "Your card was declined", "amount": "$149.00",
                       "invoice_url": "https://consentvault.ai/billing/inv"},
}


class Alarms:
    def __init__(self):
        self.rows = []

    def raise_alarm(self, name, detail):
        self.rows.append((name, detail))


@pytest.mark.parametrize("name", list(GOOD))
def test_templates_render_text_html_no_em_dash(name):
    subject, text, html = render(name, GOOD[name])
    assert "—" not in subject + text + html
    assert "Acme Floors" in text and "Acme Floors" in html
    assert html.startswith("<div")


def test_html_escapes_variables():
    v = dict(GOOD["invite"], company="A<b>&Co")
    _, _, html = render("invite", v)
    assert "<b>" not in html and "A&lt;b&gt;&amp;Co" in html


@pytest.mark.parametrize("value", ["555-123-4567", "(555) 123-4567", "+15551234567", "5551234567"])
def test_phone_like_refused(value):
    with pytest.raises(NotifyRefused, match="template variable 'company' looks like a phone number"):
        render("invite", dict(GOOD["invite"], company=value))


def test_consumer_email_refused():
    with pytest.raises(NotifyRefused, match="template variable 'inviter_name' looks like an email address"):
        render("invite", dict(GOOD["invite"], inviter_name="jane@example.com"))


def test_unknown_and_missing_variable_refused():
    with pytest.raises(NotifyRefused, match="does not take variable 'phone'"):
        render("invite", dict(GOOD["invite"], phone="x"))
    bad = dict(GOOD["invite"])
    del bad["company"]
    with pytest.raises(NotifyRefused, match="missing variable 'company'"):
        render("invite", bad)
    with pytest.raises(NotifyRefused, match="unknown template"):
        render("marketing_blast", {})


def test_dates_and_amounts_not_flagged():
    render("billing_notice", dict(GOOD["billing_notice"], amount="$1,234.00", notice="Invoice INV-2026-1029 is due"))


class FakeSender:
    provider = "fake"

    def __init__(self, fail=False):
        self.fail, self.sent = fail, []

    def send(self, m: Message):
        if self.fail:
            raise SendFailed("fake", "ProviderDown")
        self.sent.append(m)
        return "mid-1"


def test_notifier_logs_domain_only_no_body():
    log, alarms = InMemorySendLog(), Alarms()
    mid = Notifier(FakeSender(), log, alarms).send("invite", "Pat@Client.COM", GOOD["invite"])
    assert mid == "mid-1"
    r = log.records[0]
    assert (r.type, r.recipient_domain, r.outcome, r.provider_message_id) == ("invite", "client.com", "sent", "mid-1")
    assert "pat" not in repr(r).lower() and "Acme" not in repr(r)
    assert alarms.rows == []


def test_failed_send_logged_alarmed_and_raised():
    log, alarms = InMemorySendLog(), Alarms()
    with pytest.raises(SendFailed):
        Notifier(FakeSender(fail=True), log, alarms).send("security_alert", "a@b.com", GOOD["security_alert"])
    assert log.records[0].outcome == "failed"
    assert alarms.rows[0][0] == ALARM_SEND_FAILED


def test_refused_message_never_reaches_sender():
    s = FakeSender()
    with pytest.raises(NotifyRefused):
        Notifier(s, InMemorySendLog(), Alarms()).send("invite", "a@b.com", dict(GOOD["invite"], company="555-123-4567"))
    assert s.sent == []


def test_bad_recipient_refused():
    with pytest.raises(NotifyRefused, match="recipient"):
        Notifier(FakeSender(), InMemorySendLog(), Alarms()).send("invite", "nope", GOOD["invite"])


def test_bounce_logged_and_alarmed():
    log, alarms = InMemorySendLog(), Alarms()
    Notifier(FakeSender(), log, alarms).record_bounce("invite", "x@gone.org", "mid-9", "mailbox full")
    assert log.records[0].outcome == "bounced" and log.records[0].recipient_domain == "gone.org"
    assert alarms.rows[0][0] == ALARM_BOUNCE


def _ses(status=200, body=b'{"MessageId":"ses-123"}', seen=None):
    def transport(req):
        if seen is not None:
            seen.append(req)
        return HttpResponse(status, body)
    return SesSender(region="us-east-1", access_key="AKIDEXAMPLE", secret_key="secret", sender="no-reply@consentvault.ai",
                     transport=transport, clock=lambda: datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc))


def test_ses_signs_and_returns_message_id():
    seen = []
    mid = _ses(seen=seen).send(Message("a@b.com", "S", "T", "<p>H</p>"))
    assert mid == "ses-123"
    req = seen[0]
    assert req.url == "https://email.us-east-1.amazonaws.com/v2/email/outbound-emails"
    auth = req.headers["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261029/us-east-1/ses/aws4_request")
    assert "SignedHeaders=content-type;host;x-amz-date" in auth
    assert json.loads(req.body)["Destination"]["ToAddresses"] == ["a@b.com"]
    assert "secret" not in auth


def test_ses_signature_deterministic():
    a, b = [], []
    _ses(seen=a).send(Message("a@b.com", "S", "T", "H"))
    _ses(seen=b).send(Message("a@b.com", "S", "T", "H"))
    assert a[0].headers["Authorization"] == b[0].headers["Authorization"]


def test_ses_refusal_is_named():
    with pytest.raises(SendFailed, match="refused \\(code 400\\)"):  # the body is never carried
        _ses(status=400, body=b"bad").send(Message("a@b.com", "S", "T", "H"))


def test_ses_transport_error_named():
    def boom(req):
        raise ConnectionError("down")
    s = SesSender(region="us-east-1", access_key="a", secret_key="b", sender="x@y.z", transport=boom)
    with pytest.raises(SendFailed, match="ConnectionError"):
        s.send(Message("a@b.com", "S", "T", "H"))


def test_ses_config_missing():
    with pytest.raises(NotifyConfigError):
        SesSender(region="", access_key="a", secret_key="b", sender="x@y.z")


class FakeSMTP:
    instances = []
    starttls_offered = True
    fail_send = False

    def __init__(self, host, port, timeout=None):
        self.calls = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def has_extn(self, name):
        return FakeSMTP.starttls_offered

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, u, p):
        self.calls.append("login")

    def send_message(self, msg):
        if FakeSMTP.fail_send:
            raise smtplib.SMTPRecipientsRefused({})
        self.calls.append("send")
        self.msg = msg


@pytest.fixture(autouse=True)
def _reset():
    FakeSMTP.instances, FakeSMTP.starttls_offered, FakeSMTP.fail_send = [], True, False


def test_smtp_starttls_before_login_and_send():
    s = SmtpSender("mail.local", 587, "no-reply@x.io", "u", "p", smtp_factory=FakeSMTP)
    mid = s.send(Message("a@b.com", "S", "T", "<p>H</p>"))
    calls = FakeSMTP.instances[0].calls
    assert calls.index("starttls") < calls.index("login") < calls.index("send")
    assert mid.startswith("<") and FakeSMTP.instances[0].msg.is_multipart()


def test_smtp_refuses_without_starttls():
    FakeSMTP.starttls_offered = False
    s = SmtpSender("mail.local", 587, "no-reply@x.io", smtp_factory=FakeSMTP)
    with pytest.raises(NotifyConfigError, match="STARTTLS"):
        s.send(Message("a@b.com", "S", "T", "H"))
    assert "send" not in FakeSMTP.instances[0].calls


def test_smtp_failure_named():
    FakeSMTP.fail_send = True
    s = SmtpSender("mail.local", 587, "no-reply@x.io", smtp_factory=FakeSMTP)
    with pytest.raises(SendFailed, match="SMTPRecipientsRefused"):
        s.send(Message("a@b.com", "S", "T", "H"))


# ---- second-wave review: a refused recipient's address never reaches the log or the alarm --------------------------
def test_a_refused_recipients_address_never_reaches_the_log_or_alarm():
    address = "jane.doe@client-example.com"

    class Refusing(FakeSMTP):
        def send_message(self, msg):
            raise smtplib.SMTPRecipientsRefused({address: (550, f"5.1.1 <{address}>: Recipient address rejected".encode())})

    log, alarms = InMemorySendLog(), Alarms()
    sender = SmtpSender("mail.local", 587, "no-reply@x.io", smtp_factory=Refusing)
    with pytest.raises(SendFailed) as caught:
        Notifier(sender, log, alarms).send("security_alert", address, GOOD["security_alert"])
    assert caught.value.code == 550 and caught.value.__cause__ is None
    seen = repr(log.records) + repr(alarms.rows) + str(caught.value)
    assert "jane" not in seen.lower() and "rejected" not in seen.lower()
    assert log.records[0].detail == "SMTPRecipientsRefused code 550"
    assert alarms.rows == [(ALARM_SEND_FAILED, "security_alert to client-example.com failed: SMTPRecipientsRefused code 550")]


def test_an_ses_refusal_body_never_reaches_the_log():
    log, alarms = InMemorySendLog(), Alarms()
    with pytest.raises(SendFailed):
        Notifier(_ses(status=400, body=b"Address blocked: jane.doe@client-example.com"), log, alarms).send(
            "invite", "jane.doe@client-example.com", GOOD["invite"])
    assert "jane" not in (repr(log.records) + repr(alarms.rows)).lower()
