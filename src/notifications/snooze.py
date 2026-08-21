"""Snooze unread notifications until a deadline."""

from __future__ import annotations

import time

from src.notifications.inbox import Inbox


class SnoozeBook:
    def __init__(self) -> None:
        self._until: dict[str, float] = {}

    def snooze(self, notification_id: str, seconds: float, *, now: float | None = None) -> None:
        epoch = float(now if now is not None else time.time())
        self._until[notification_id] = epoch + max(0.0, seconds)

    def hidden(self, notification_id: str, *, now: float | None = None) -> bool:
        epoch = float(now if now is not None else time.time())
        deadline = self._until.get(notification_id)
        if deadline is None:
            return False
        if epoch >= deadline:
            self._until.pop(notification_id, None)
            return False
        return True

    def visible(self, inbox: Inbox, *, now: float | None = None) -> list[str]:
        return [
            item.notification_id
            for item in inbox.list(limit=500)
            if not self.hidden(item.notification_id, now=now)
        ]
