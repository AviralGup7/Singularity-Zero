"""Public API for package-level tool execution.

All existing ``from src.pipeline.services.tool_execution import <X>`` patterns
continue to work because every previously public symbol is re-exported here.

Sub-modules
-----------
contracts
    Pure data classes: ``ToolInvocation``, ``CompletedToolRun``,
    ``ToolExecutionOutcome``, ``ToolExecutionError``.
runner
    Low-level helpers, the module-level circuit-breaker registry, the shared
    thread-pool executor, and the async ``run_external_tool()`` entry point.
service
    ``ToolExecutionService`` — high-level facade with retry, circuit-breaker
    management, tool resolution, and sanitization.
"""

from __future__ import annotations

# Re-export everything that callers could previously import directly from this
# package (i.e. from ``src.pipeline.services.tool_execution``).

# stdlib — re-exported so ``patch("src.pipeline.services.tool_execution.subprocess.run")``
# continues to work in existing tests.
import subprocess

from .contracts import (
    CompletedToolRun,
    ToolExecutionError,
    ToolExecutionOutcome,
    ToolInvocation,
)

# Module-level helpers (present on the original flat module).
from .runner import (
    SHELL_META,
    _clean_env,
    _coerce_output_text,
    get_circuit_breaker,
)
from .service import ToolExecutionService
from .runner import run_external_tool  # noqa: E402  (pull async runner after service for ordering)

# Re-export symbols that callers import *from* this package but which are
# actually defined in sibling modules (circuit_breaker, retry, waf_profile).
from src.pipeline.retry import RetryPolicy
from src.pipeline.services.circuit_breaker import (
    CircuitBreakerConfig,
    CircuitBreakerStats,
    ProbeCallback,
)
from src.pipeline.waf_profile import WafTuningProfile

__all__ = [
    # Contracts
    "ToolInvocation",
    "CompletedToolRun",
    "ToolExecutionOutcome",
    "ToolExecutionError",
    # Service
    "ToolExecutionService",
    # Async runner
    "run_external_tool",
    # Module-level helpers
    "SHELL_META",
    "_clean_env",
    "_get_creationflags",
    "_coerce_output_text",
    "get_circuit_breaker",
    # Re-exported for tests / dashboard compatibility
    "RetryPolicy",
    "CircuitBreakerConfig",
    "CircuitBreakerStats",
    "ProbeCallback",
    "WafTuningProfile",
    "subprocess",
]
