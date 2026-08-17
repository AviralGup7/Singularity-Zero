"""Coverage and regression for self-healing history + dampening."""

from __future__ import annotations

import pytest

from src.core.contracts.health import CorrectiveAction, HealthComponent
from src.pipeline.self_healing.dampening import DampeningWindow
from src.pipeline.self_healing.history_store import CorrectionHistoryStore


@pytest.mark.unit
def test_history_store_escalates_on_failure_rate() -> None:
    store = CorrectionHistoryStore(window_size=10, failure_threshold=0.40)
    action = CorrectiveAction.REFRESH_STUCK_STAGE
    assert store.should_escalate(action) is False
    store.record(action, False)
    store.record(action, False)
    assert store.should_escalate(action) is False
    store.record(action, False)
    assert store.should_escalate(action) is True
    store.record(action, True)
    store.record(action, True)
    store.record(action, True)
    store.record(action, True)
    store.record(action, True)
    assert store.should_escalate(action) is False


@pytest.mark.unit
def test_history_store_small_window_can_still_escalate() -> None:
    store = CorrectionHistoryStore(window_size=2, failure_threshold=0.50)
    action = CorrectiveAction.RESTART_WORKER
    store.record(action, False)
    assert store.should_escalate(action) is False
    store.record(action, False)
    assert store.should_escalate(action) is True
    store.record(action, True)
    store.record(action, True)
    assert store.should_escalate(action) is False


@pytest.mark.unit
def test_dampening_window_suppresses_until_cooldown() -> None:
    window = DampeningWindow(default_cooldown_seconds=10.0)
    action = CorrectiveAction.FLUSH_BLOOM_FILTER
    component = HealthComponent.BLOOM_MESH
    assert window.should_suppress(action, component, now=100.0) is False
    window.record_fire(action, component, now=100.0)
    assert window.should_suppress(action, component, now=105.0) is True
    assert window.should_suppress(action, component, now=111.0) is False
    window.configure_cooldown(action, component, 1.0)
    window.record_fire(action, component, now=200.0)
    assert window.should_suppress(action, component, now=200.5) is True
    assert window.should_suppress(action, component, now=201.1) is False
    window.clear()
    assert window.should_suppress(action, component, now=201.1) is False
