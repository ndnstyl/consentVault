"""The sender interface, the send log interface and the alarm interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

TEMPLATE_TYPES = ("invite", "security_alert", "delivery_failure", "billing_notice")


@dataclass(frozen=True)
class Message:
    to: str
    subject: str
    text: str
    html: str
    template: str | None = None  # the template type; SES tags the send with it so a bounce can name it


class Sender(Protocol):
    provider: str

    def send(self, message: Message) -> str:
        """Send one message and return the provider message id. Raise SendFailed on any refusal."""


@dataclass(frozen=True)
class SendRecord:
    """One row of the send log. No body, no full address: type, recipient domain, outcome, provider id."""

    type: str
    recipient_domain: str
    outcome: str  # "sent", "failed", "bounced"
    provider: str
    provider_message_id: str | None
    detail: str | None = None
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SendLog(Protocol):
    def append(self, record: SendRecord) -> None: ...


class Alarm(Protocol):
    def raise_alarm(self, name: str, detail: str) -> None: ...


class InMemorySendLog:
    def __init__(self) -> None:
        self.records: list[SendRecord] = []

    def append(self, record: SendRecord) -> None:
        # The Postgres log's rule (migration 0063): one bounced row per provider message.
        if record.outcome == "bounced" and any(r.outcome == "bounced" and (r.provider, r.provider_message_id) ==
                                               (record.provider, record.provider_message_id) for r in self.records):
            return
        self.records.append(record)
