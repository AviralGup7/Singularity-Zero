from __future__ import annotations

from pathlib import Path

from src.resilience import BreakerStore, CircuitState, ProbeDispatcher, ToolCircuitBreaker
from src.resilience.metrics import ResilienceMetrics


def test_breaker_roundtrip(tmp_path: Path) -> None:
    breaker = ToolCircuitBreaker(failure_threshold=2, recovery_timeout=30)
    breaker.record_failure("nuclei", "timeout")
    breaker.record_failure("nuclei", "timeout")
    assert breaker.get_state("nuclei") is CircuitState.OPEN
    store = BreakerStore(tmp_path / "breaker.json")
    store.save(breaker)
    clone = ToolCircuitBreaker()
    assert store.load(clone) is True
    assert clone.get_state("nuclei") is CircuitState.OPEN


def test_probe_recovers_open_tool() -> None:
    breaker = ToolCircuitBreaker(failure_threshold=1, recovery_timeout=0.0)
    breaker.record_failure("gau", "timeout")
    metrics = ResilienceMetrics()
    dispatcher = ProbeDispatcher(breaker, metrics)
    dispatcher.register("gau", lambda: True)
    # recovery_timeout 0 lets can_execute enter HALF_OPEN
    results = dispatcher.run_due()
    assert "gau" in results
    metrics.observe_breaker(breaker, "gau")
    assert isinstance(metrics.to_dict()["opens"], int)
