"""Escalate unread critical notifications."""

from __future__ import annotations

import time

from src.notifications.events import NotificationPriority
from src.notifications.inbox import Inbox


def overdue_critical(inbox: Inbox, *, older_than: float, now: float | None = None) -> list[str]:
    epoch = float(now if now is not None else time.time())
    overdue: list[str] = []
    for item in inbox.high_priority():
        if item.read:
            continue
        if item.priority is not NotificationPriority.CRITICAL:
            continue
        if epoch - item.created_at >= older_than:
            overdue.append(item.notification_id)
    return overdue


def escalate_count(inbox: Inbox, *, older_than: float = 300.0) -> int:
    return len(overdue_critical(inbox, older_than=older_than))
