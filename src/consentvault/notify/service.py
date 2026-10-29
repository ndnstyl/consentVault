"""Notifier: render, refuse unsafe content, send, log, and alarm on a failed send or a bounce."""

from __future__ import annotations

from .base import Alarm, Message, SendLog, SendRecord, Sender
from .errors import NotifyRefused, SendFailed
from .templates import render

ALARM_SEND_FAILED = "notify.send_failed"
ALARM_BOUNCE = "notify.bounce"


def recipient_domain(address: str) -> str:
    local, sep, domain = address.strip().rpartition("@")
    if not sep or not local or "." not in domain or " " in domain:
        raise NotifyRefused("recipient is not a valid email address")
    return domain.lower()


class Notifier:
    def __init__(self, sender: Sender, log: SendLog, alarm: Alarm) -> None:
        self._sender, self._log, self._alarm = sender, log, alarm

    def send(self, template: str, to: str, variables: dict) -> str:
        domain = recipient_domain(to)
        subject, text, html = render(template, variables)
        try:
            msg_id = self._sender.send(Message(to=to, subject=subject, text=text, html=html))
        except SendFailed as exc:
            # type and provider code only: a provider's message can quote the recipient's address
            safe = f"{exc.kind}" + (f" code {exc.code}" if exc.code is not None else "")
            self._log.append(SendRecord(template, domain, "failed", self._sender.provider, None, safe))
            self._alarm.raise_alarm(ALARM_SEND_FAILED, f"{template} to {domain} failed: {safe}")
            raise
        self._log.append(SendRecord(template, domain, "sent", self._sender.provider, msg_id))
        return msg_id

    def record_bounce(self, template: str, recipient: str, provider_message_id: str, reason: str = "") -> None:
        domain = recipient_domain(recipient)
        self._log.append(SendRecord(template, domain, "bounced", self._sender.provider, provider_message_id,
                                    reason[:200] or None))
        self._alarm.raise_alarm(ALARM_BOUNCE, f"{template} to {domain} bounced (message {provider_message_id})")
