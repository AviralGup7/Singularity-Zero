"""HALF_OPEN recovery probes."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from src.resilience.circuit_breaker import CircuitState, ToolCircuitBreaker
from src.resilience.metrics import ResilienceMetrics


Probe = Callable[[], bool]


@dataclass
class ProbePlan:
    tool_name: str
    probe: Probe


class ProbeDispatcher:
    def __init__(self, breaker: ToolCircuitBreaker, metrics: ResilienceMetrics | None = None) -> None:
        self.breaker = breaker
        self.metrics = metrics or ResilienceMetrics()
        self._plans: dict[str, Probe] = {}

    def register(self, tool_name: str, probe: Probe) -> None:
        self._plans[tool_name] = probe

    def pending(self) -> list[str]:
        names: list[str] = []
        for tool_name in self._plans:
            if self.breaker.get_state(tool_name) is CircuitState.HALF_OPEN:
                names.append(tool_name)
            elif self.breaker.can_execute(tool_name) and self.breaker.get_state(tool_name) is CircuitState.HALF_OPEN:
                names.append(tool_name)
        return names

    def run_due(self) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for tool_name, probe in list(self._plans.items()):
            state = self.breaker.get_state(tool_name)
            if state is CircuitState.CLOSED:
                continue
            if not self.breaker.can_execute(tool_name) and state is CircuitState.OPEN:
                continue
            self.metrics.record_probe()
            try:
                ok = bool(probe())
            except Exception:
                ok = False
            if ok:
                self.breaker.record_success(tool_name)
            else:
                self.breaker.record_failure(tool_name, "probe_failed")
            self.metrics.observe_breaker(self.breaker, tool_name)
            results[tool_name] = ok
        return results
