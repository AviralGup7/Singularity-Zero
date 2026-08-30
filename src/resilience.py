"""Compat module path for atlas citations of ``resilience.py``.

The package lives at :mod:`src.resilience`. This file exists so plain
``import src.resilience`` module path references in docs resolve.
"""

from __future__ import annotations

# Re-export common breaker symbols when available.
try:
    from src.resilience.circuit_breaker import ToolCircuitBreaker  # noqa: F401
except Exception:  # pragma: no cover
    ToolCircuitBreaker = None  # type: ignore[misc, assignment]

__all__ = ["ToolCircuitBreaker"]
