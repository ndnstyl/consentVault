"""Adapter interfaces. The core knows contact points, channels and purposes; nothing vendor-specific."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, Sequence, runtime_checkable


@dataclass(frozen=True)
class PermissionChange:
    """One permission change to push to an outside system."""

    contact_norm: str
    contact_kind: str
    channel: str
    purpose: str
    allowed: bool
    reason: str
    event_id: str | None = None
    changed_at: datetime | None = None


@dataclass(frozen=True)
class StopMessage:
    """An inbound message pulled from a messaging provider that may be a stop request."""

    contact: str
    channel: str
    text: str
    received_at: datetime | None = None
    provider_ref: str | None = None
    extra: dict = field(default_factory=dict)


@runtime_checkable
class CrmAdapter(Protocol):
    """Pushes permission changes into a system of record."""

    name: str

    def push_permission_change(self, change: PermissionChange) -> None:
        """Deliver one change. Raise AdapterError if it was not delivered."""
        ...


@runtime_checkable
class MessagingAdapter(Protocol):
    """Pulls inbound stop messages from a messaging provider."""

    name: str

    def pull_stop_messages(self, since: datetime | None = None) -> Sequence[StopMessage]:
        """Return inbound messages since the given time. Raise AdapterError if the pull failed."""
        ...
