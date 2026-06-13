"""Tool execution protocol for the core layer.

This module provides a protocol for tool execution services that allows
higher layers (dashboard) to depend on an interface rather than concrete
implementations from pipeline.
"""

from __future__ import annotations

from typing import Any, Protocol


class CircuitBreakerStatsProtocol(Protocol):
    """Protocol for circuit breaker statistics."""

    @property
    def state(self) -> str:
        """Return the circuit breaker state (OPEN, CLOSED, HALF_OPEN)."""
        ...

    @property
    def forced_open(self) -> bool:
        """Check if the breaker was force-opened."""
        ...

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable dictionary of the breaker stats."""
        ...


class CircuitBreakerProtocol(Protocol):
    """Protocol for circuit breakers."""

    def stats(self) -> CircuitBreakerStatsProtocol:
        """Return the current breaker statistics."""
        ...


class ToolExecutionServiceProtocol(Protocol):
    """Protocol for tool execution services.

    This protocol defines the interface that dashboard and other layers
    can depend on without importing concrete implementations from pipeline.
    """

    def breaker_snapshot(self) -> dict[str, CircuitBreakerStatsProtocol]:
        """Return a snapshot of all circuit breaker states."""
        ...

    def force_open_breaker(
        self,
        tool_name: str,
        reason: str,
        *,
        duration_seconds: int | None = None,
    ) -> CircuitBreakerProtocol:
        """Force open a tool's circuit breaker."""
        ...

    def reset_breaker(self, tool_name: str) -> CircuitBreakerProtocol:
        """Reset a tool's circuit breaker back to CLOSED."""
        ...

    def check_tool_availability(self, tool_name: str) -> bool:
        """Check if a tool is available."""
        ...

    def check_tools_availability(self, tool_names: list[str]) -> dict[str, bool]:
        """Check availability of multiple tools."""
        ...
