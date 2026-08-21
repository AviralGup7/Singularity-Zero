"""Filter notifications by priority / event / text."""

from __future__ import annotations

from dataclasses import dataclass

from src.notifications.events import Notification, NotificationEvent, NotificationPriority


@dataclass(frozen=True, slots=True)
class NotificationFilter:
    unread_only: bool = False
    min_priority: NotificationPriority | None = None
    event: NotificationEvent | None = None
    text: str | None = None


_RANK = {
    NotificationPriority.LOW: 0,
    NotificationPriority.NORMAL: 1,
    NotificationPriority.HIGH: 2,
    NotificationPriority.CRITICAL: 3,
}


def matches(item: Notification, spec: NotificationFilter) -> bool:
    if spec.unread_only and item.read:
        return False
    if spec.event is not None and item.event is not spec.event:
        return False
    if spec.min_priority is not None and _RANK[item.priority] < _RANK[spec.min_priority]:
        return False
    if spec.text:
        blob = f"{item.title} {item.message}".lower()
        if spec.text.lower() not in blob:
            return False
    return True


def apply_filter(items: list[Notification], spec: NotificationFilter) -> list[Notification]:
    return [item for item in items if matches(item, spec)]
