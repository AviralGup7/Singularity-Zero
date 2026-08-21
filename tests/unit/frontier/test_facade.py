from __future__ import annotations

from src.frontier import hybrid_clock_cls, new_state


def test_new_state_is_empty_crdt() -> None:
    state = new_state()
    snapshot = state.get_snapshot()
    assert snapshot["subdomains"] == []
    assert snapshot["urls"] == []
    assert snapshot["findings"] == []


def test_hybrid_clock_ticks() -> None:
    clock = hybrid_clock_cls()()
    later = clock.tick()
    assert later.is_later_than(clock) or later.physical_time >= clock.physical_time
