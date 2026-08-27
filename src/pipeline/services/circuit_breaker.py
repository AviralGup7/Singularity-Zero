"""Compatibility shim. Canonical breaker is ``src.resilience.circuit_breaker``."""
from __future__ import annotations

from src.resilience.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerStats,
    CircuitState,
    ProbeCallback,
    load_all_breakers,
    load_breaker_state,
    persist_all_breakers,
    persist_breaker_state,
)

__all__ = [
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerStats",
    "CircuitState",
    "ProbeCallback",
    "load_all_breakers",
    "load_breaker_state",
    "persist_all_breakers",
    "persist_breaker_state",
]

