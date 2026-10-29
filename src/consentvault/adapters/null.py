"""Adapters that do nothing: the default for installs with no CRM or messaging provider."""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from .base import PermissionChange, StopMessage


class NullCrmAdapter:
    name = "null"

    def __init__(self) -> None:
        self.pushed: list[PermissionChange] = []

    def push_permission_change(self, change: PermissionChange) -> None:
        self.pushed.append(change)


class NullMessagingAdapter:
    name = "null"

    def pull_stop_messages(self, since: datetime | None = None) -> Sequence[StopMessage]:
        return []
