"""UNUSED on the live scan path.

Perfection-suite DomainEvent bus. The live CLI/dashboard bus is
``src.core.events.event_bus`` (re-exported from ``src.core.events``).
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable

from src.core.events.events import DomainEvent

logger = logging.getLogger(__name__)

EventHandler = Callable[[DomainEvent], Awaitable[None] | None]


class EventBus:
    """High-performance async publish-subscribe event bus."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[EventHandler]] = defaultdict(list)
        self._global_subscribers: list[EventHandler] = []

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        self._subscribers[event_type].append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        self._global_subscribers.append(handler)

    async def publish(self, event: DomainEvent) -> None:
        """Broadcast event to type-specific and global handlers concurrently."""
        handlers = self._subscribers.get(event.event_type, []) + self._global_subscribers
        if not handlers:
            return

        for handler in handlers:
            try:
                res = handler(event)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as exc:
                logger.warning("EventBus handler error for %s: %s", event.event_type, exc)


__all__ = [
    "EventBus",
    "EventHandler",
]
