"""In-memory notification inbox."""

from __future__ import annotations

import builtins
import threading
from collections.abc import Callable
from typing import Any

from src.auth.session import Session
from src.notifications.events import Notification, NotificationEvent, NotificationPriority
from src.notifications.policy import should_fetch


class Inbox:
    def __init__(self, *, limit: int = 500) -> None:
        self._limit = max(32, int(limit))
        self._lock = threading.RLock()
        self._items: list[Notification] = []
        self._listeners: list[Callable[[Notification], None]] = []

    def subscribe(self, listener: Callable[[Notification], None]) -> None:
        with self._lock:
            self._listeners.append(listener)

    def push(self, notification: Notification) -> Notification:
        with self._lock:
            self._items.insert(0, notification)
            if len(self._items) > self._limit:
                self._items = self._items[: self._limit]
        for listener in list(self._listeners):
            listener(notification)
        return notification

    def list(
        self,
        *,
        unread_only: bool = False,
        event: NotificationEvent | None = None,
        limit: int = 100,
        offset: int = 0,
        spec: Any = None,
    ) -> builtins.list[Notification]:
        with self._lock:
            items = list(self._items)
        if spec is not None:
            from src.notifications.filters import apply_filter

            items = apply_filter(items, spec)
        if unread_only:
            items = [item for item in items if not item.read]
        if event is not None:
            items = [item for item in items if item.event is event]
        start = max(0, offset)
        return items[start : start + max(1, limit)]

    def overdue_critical_ids(self, *, older_than: float, now: float | None = None) -> list[str]:
        from src.notifications.escalation import overdue_critical

        return overdue_critical(self, older_than=older_than, now=now)

    def unread_count(self) -> int:
        with self._lock:
            return sum(1 for item in self._items if not item.read)

    def get(self, notification_id: str) -> Notification | None:
        with self._lock:
            for item in self._items:
                if item.notification_id == notification_id:
                    return item
        return None

    def mark_read(self, notification_id: str) -> bool:
        item = self.get(notification_id)
        if item is None:
            return False
        item.mark_read()
        return True

    def mark_all_read(self) -> int:
        with self._lock:
            changed = 0
            for item in self._items:
                if not item.read:
                    item.mark_read()
                    changed += 1
            return changed

    def delete(self, notification_id: str) -> bool:
        with self._lock:
            before = len(self._items)
            self._items = [item for item in self._items if item.notification_id != notification_id]
            return len(self._items) < before

    def clear(self) -> int:
        with self._lock:
            count = len(self._items)
            self._items.clear()
            return count

    def visible_to(self, session: Session | None) -> bool:
        return should_fetch(session)

    def high_priority(self) -> list[Notification]:
        with self._lock:
            return [
                item
                for item in self._items
                if item.priority in {NotificationPriority.HIGH, NotificationPriority.CRITICAL}
            ]

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)
