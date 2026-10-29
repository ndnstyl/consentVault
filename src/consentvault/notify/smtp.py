"""SMTP sender for self-host. STARTTLS is required; there is no plaintext fallback."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid

from .base import Message
from .errors import NotifyConfigError, SendFailed


def smtp_code(exc: BaseException) -> int | None:
    """The SMTP reply code of a refusal, without its text (which can quote the address)."""
    code = getattr(exc, "smtp_code", None)
    if isinstance(code, int):
        return code
    recipients = getattr(exc, "recipients", None)
    if isinstance(recipients, dict):
        codes = [v[0] for v in recipients.values() if isinstance(v, tuple) and v and isinstance(v[0], int)]
        return codes[0] if codes else None
    return None


class SmtpSender:
    provider = "smtp"

    def __init__(self, host: str, port: int, sender: str, username: str | None = None,
                 password: str | None = None, timeout: float = 20.0, smtp_factory=smtplib.SMTP) -> None:
        if not host or not sender:
            raise NotifyConfigError("SMTP sender needs a host and a from address")
        self.host, self.port, self.sender = host, port, sender
        self.username, self.password, self.timeout = username, password, timeout
        self._factory = smtp_factory

    def send(self, message: Message) -> str:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.sender, message.to, message.subject
        msg_id = make_msgid(domain=self.sender.rsplit("@", 1)[-1])
        msg["Message-ID"] = msg_id
        msg.set_content(message.text)
        msg.add_alternative(message.html, subtype="html")
        try:
            with self._factory(self.host, self.port, timeout=self.timeout) as smtp:
                smtp.ehlo()
                if not smtp.has_extn("starttls"):
                    raise NotifyConfigError(f"SMTP server {self.host} does not offer STARTTLS; refusing to send")
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                if self.username:
                    smtp.login(self.username, self.password or "")
                smtp.send_message(msg)
        except NotifyConfigError:
            raise
        except (smtplib.SMTPException, OSError) as exc:
            raise SendFailed("smtp", type(exc).__name__, smtp_code(exc)) from None  # never the server's text
        return msg_id
