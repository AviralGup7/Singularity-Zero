"""Live EventBus must keep finding events and cap recursive fan-out."""

from __future__ import annotations

from src.core.events.event_bus import EventBus, EventType, get_event_bus, reset_event_bus


def test_fanout_depth_drops_non_critical_recursive_emit() -> None:
    bus = EventBus()
    seen: list[str] = []

    def handler(event: object) -> None:
        seen.append(str(getattr(event, "event_type")))
        if len(seen) < 20:
            bus.emit(EventType.STAGE_PROGRESS, source="nested")

    bus.subscribe(EventType.STAGE_PROGRESS, handler)
    bus.emit(EventType.STAGE_PROGRESS, source="root")
    assert 1 <= len(seen) <= EventBus._FANOUT_MAX_DEPTH
    assert bus.dropped_status()["dropped_fanout"] >= 1


def test_critical_finding_events_are_not_dropped_at_depth() -> None:
    bus = EventBus()
    findings: list[str] = []

    def progress_handler(event: object) -> None:
        bus.emit(EventType.FINDING_CREATED, source="nested", data={"n": len(findings)})

    def finding_handler(event: object) -> None:
        findings.append("ok")

    bus.subscribe(EventType.STAGE_PROGRESS, progress_handler)
    bus.subscribe(EventType.FINDING_CREATED, finding_handler)
    bus.emit(EventType.STAGE_PROGRESS, source="root")
    assert findings, "FINDING_CREATED must still be delivered under fan-out pressure"


def test_reset_event_bus_clears_process_singleton() -> None:
    first = get_event_bus()
    reset_event_bus()
    second = get_event_bus()
    assert first is not second
    reset_event_bus()
