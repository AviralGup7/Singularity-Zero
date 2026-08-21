"""Inbox metrics."""

from __future__ import annotations

from src.notifications.events import NotificationPriority
from src.notifications.inbox import Inbox


def inbox_stats(inbox: Inbox) -> dict[str, int]:
    items = inbox.list(limit=500)
    return {
        "total": len(items),
        "unread": inbox.unread_count(),
        "critical": sum(1 for item in items if item.priority is NotificationPriority.CRITICAL),
        "high": sum(1 for item in items if item.priority is NotificationPriority.HIGH),
    }
