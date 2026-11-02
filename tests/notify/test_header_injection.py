"""No control character, CR and LF included, reaches the subject or any header field of a product email.

Every template variable is a single-line value, so a variable carrying any control character (C0, DEL, C1, and the Unicode
line and paragraph separators) is refused before rendering; the recipient and the From address are checked the same way,
and the senders check the subject and both addresses again just before the provider call. Nothing is sent and the refusal
is ``NotifyRefused``."""

import pytest

from consentvault.notify import InMemorySendLog, Message, Notifier, NotifyRefused, SesSender, SmtpSender, render
from consentvault.notify.errors import NotifyConfigError
from consentvault.notify.ses import HttpResponse

from .test_notify import GOOD, Alarms

BAD = ["\r", "\n", "\r\nBcc: x@evil.example", "\x00", "\x07", "\t", "\x1b", "\x7f", "\x85", " ", " "]


class Sender:
    provider = "fake"

    def __init__(self):
        self.sent = []

    def send(self, m):
        self.sent.append(m)
        return "id"


@pytest.mark.parametrize("bad", BAD)
@pytest.mark.parametrize("template", list(GOOD))
def test_every_variable_of_every_template_refuses_a_control_character(template, bad):
    for name in GOOD[template]:
        with pytest.raises(NotifyRefused, match="control character"):
            render(template, {**GOOD[template], name: GOOD[template][name] + bad + "x"})


@pytest.mark.parametrize("bad", BAD)
def test_a_recipient_with_a_control_character_is_refused_and_nothing_is_sent(bad):
    s, log = Sender(), InMemorySendLog()
    with pytest.raises(NotifyRefused, match="control character"):
        Notifier(s, log, Alarms()).send("invite", "pat@client.com" + bad, GOOD["invite"])
    assert s.sent == [] and log.records == []


@pytest.mark.parametrize("bad", BAD)
def test_the_ses_sender_refuses_a_control_character_in_the_subject_or_either_address(bad):
    seen = []
    s = SesSender(region="us-east-1", sender="no-reply@consentvault.ai", access_key="a", secret_key="b",
                  transport=lambda r: seen.append(r) or HttpResponse(200, b'{"MessageId":"m"}'))
    for m in (Message("a@b.com", "Hi" + bad, "t", "h"), Message("a@b.com" + bad, "Hi", "t", "h")):
        with pytest.raises(NotifyRefused, match="control character"):
            s.send(m)
    assert seen == []
    with pytest.raises(NotifyConfigError, match="control character"):
        SesSender(region="us-east-1", sender="no-reply@consentvault.ai" + bad, access_key="a", secret_key="b")


@pytest.mark.parametrize("bad", ["\r\n", "\n", "\x00"])
def test_the_smtp_sender_refuses_a_control_character_in_the_subject_or_either_address(bad):
    s = SmtpSender.__new__(SmtpSender)
    s.sender = "no-reply@consentvault.ai"
    for m in (Message("a@b.com", "Hi" + bad, "t", "h"), Message("a@b.com" + bad, "Hi", "t", "h")):
        with pytest.raises(NotifyRefused, match="control character"):
            s.send(m)


def test_a_multi_line_body_is_still_rendered_by_the_template_itself():
    subject, text, _ = render("invite", GOOD["invite"])
    assert "\n" in text and "\n" not in subject and "\r" not in subject
