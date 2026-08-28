"""Compatibility shim. Canonical breaker is ``src.resilience.circuit_breaker``."""

from __future__ import annotations

from src.resilience.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
)

__all__ = [
    "CircuitBreaker",
    "CircuitBreakerOpenError",
    "CircuitState",
]
