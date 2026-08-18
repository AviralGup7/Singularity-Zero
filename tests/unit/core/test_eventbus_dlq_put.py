"""Regression: failed handlers must enqueue the event on the DLQ."""

from __future__ import annotations

import pytest

from src.core.events.event_bus import Event, EventBus, EventHandler, Subscription


class _Boom(EventHandler):
    @property
    def event_types(self) -> list[str]:
        return ["x"]

    async def handle(self, event: Event) -> None:
        raise RuntimeError("boom")


@pytest.mark.asyncio
@pytest.mark.unit
async def test_failed_handler_puts_on_dlq_without_awaiting_put_nowait() -> None:
    bus = EventBus()
    event = Event(type="x", payload={"a": 1})
    await bus._safe_handle(Subscription(handler=_Boom(), event_types=["x"]), event)
    assert bus._dlq.qsize() == 1
    assert bus.get_metrics()["failed"] == 1
    assert bus._dlq.get_nowait().id == event.id
