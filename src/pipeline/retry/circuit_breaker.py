"""Compatibility shim. Canonical breaker is ``src.resilience.circuit_breaker``."""

from src.resilience.circuit_breaker import CircuitState, ToolCircuitBreaker

__all__ = ["CircuitState", "ToolCircuitBreaker"]
