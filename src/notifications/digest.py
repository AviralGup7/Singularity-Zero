"""Roll notifications into a digest for quiet hours / email."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from src.notifications.events import Notification, NotificationEvent, NotificationPriority
from src.notifications.inbox import Inbox


@dataclass(frozen=True, slots=True)
class Digest:
    total: int
    unread: int
    by_event: dict[str, int]
    by_priority: dict[str, int]
    headlines: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "unread": self.unread,
            "by_event": dict(self.by_event),
            "by_priority": dict(self.by_priority),
            "headlines": list(self.headlines),
        }


def build_digest(inbox: Inbox, *, headline_limit: int = 5) -> Digest:
    items = inbox.list(limit=500)
    events = Counter(item.event.value for item in items)
    priorities = Counter(item.priority.value for item in items)
    headlines = tuple(
        item.title
        for item in items
        if item.priority in {NotificationPriority.CRITICAL, NotificationPriority.HIGH}
    )[:headline_limit]
    if not headlines:
        headlines = tuple(item.title for item in items[:headline_limit])
    return Digest(
        total=len(items),
        unread=inbox.unread_count(),
        by_event=dict(events),
        by_priority=dict(priorities),
        headlines=headlines,
    )


def critical_finding_burst(items: list[Notification], *, window: int = 10) -> bool:
    recent = items[:window]
    return sum(1 for item in recent if item.event is NotificationEvent.CRITICAL_FINDING) >= 3
