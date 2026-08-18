"""Regression: EventBus handler keys must use __qualname__."""

from __future__ import annotations

import pytest

from src.core.events import EventBus, EventType, PipelineEvent


def _boom(_event: PipelineEvent) -> None:
    raise RuntimeError("fail")


@pytest.mark.unit
def test_handler_key_includes_qualname() -> None:
    bus = EventBus()
    key = bus._handler_key(_boom)
    assert "_boom" in key
    assert "?" not in key.split(":")[0]


@pytest.mark.unit
def test_failing_handler_trips_circuit() -> None:
    bus = EventBus()
    bus._FALING_HANDLER_THRESHOLD = 2
    bus.subscribe(EventType.STAGE_FAILED, _boom)
    event = PipelineEvent(event_type=EventType.STAGE_FAILED, source="t")
    bus.publish(event)
    bus.publish(event)
    assert bus._is_handler_circuit_broken(_boom) is True
    # third publish must skip the broken handler without incrementing further
    before = bus.failed_handlers_count
    bus.publish(event)
    assert bus.failed_handlers_count == before
