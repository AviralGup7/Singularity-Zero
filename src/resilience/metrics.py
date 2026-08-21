"""Circuit / retry counters."""

from __future__ import annotations

from dataclasses import dataclass, field

from src.resilience.circuit_breaker import CircuitState, ToolCircuitBreaker


@dataclass
class ResilienceMetrics:
    opens: int = 0
    closes: int = 0
    probes: int = 0
    blocked_calls: int = 0
    retry_after_overrides: int = 0
    tools_open: list[str] = field(default_factory=list)

    def observe_breaker(self, breaker: ToolCircuitBreaker, tool_name: str) -> None:
        state = breaker.get_state(tool_name)
        if state is CircuitState.OPEN:
            if tool_name not in self.tools_open:
                self.tools_open.append(tool_name)
                self.opens += 1
        elif tool_name in self.tools_open:
            self.tools_open.remove(tool_name)
            self.closes += 1

    def record_block(self) -> None:
        self.blocked_calls += 1

    def record_probe(self) -> None:
        self.probes += 1

    def record_retry_after(self) -> None:
        self.retry_after_overrides += 1

    def to_dict(self) -> dict[str, object]:
        return {
            "opens": self.opens,
            "closes": self.closes,
            "probes": self.probes,
            "blocked_calls": self.blocked_calls,
            "retry_after_overrides": self.retry_after_overrides,
            "tools_open": list(self.tools_open),
        }
