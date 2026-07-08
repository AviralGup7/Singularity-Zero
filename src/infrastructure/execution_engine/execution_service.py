"""Unified ExecutionService — single access point for all thread/process pools.

Wraps existing executors (shared_pool, tool_exec, cache) without modifying
their behavior. Callers can migrate to this service over time; existing
pools remain available directly.

This module lives in infrastructure but must NOT import from pipeline.
Tool executor access is injected via a factory callable registered at
startup, preserving the dependency rule: infrastructure must not import
pipeline.
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import Any

from src.infrastructure.execution_engine.shared_pool import (
    get_shared_executor,
    run_in_shared_executor,
    shared_pool_stats,
)

logger = logging.getLogger(__name__)

_tool_executor_factory: Any = None


def register_tool_executor_factory(factory: Any) -> None:
    """Register the callable that returns the tool ThreadPoolExecutor.

    Called at startup by the pipeline layer to inject its executor
    without creating a circular import.
    """
    global _tool_executor_factory
    _tool_executor_factory = factory


class ExecutionService:
    """Facade for all execution pools in the system.

    Provides named access to pools. Each pool is lazily initialized and
    remains a separate executor — this service does NOT merge them.

    Usage::

        from src.infrastructure.execution_engine.execution_service import get_execution_service

        svc = get_execution_service()
        io_pool = svc.io_pool
        tool_pool = svc.tool_pool
    """

    def __init__(self) -> None:
        self._tool_pool: concurrent.futures.ThreadPoolExecutor | None = None
        self._cache_pool: concurrent.futures.ThreadPoolExecutor | None = None

    @property
    def io_pool(self) -> concurrent.futures.ThreadPoolExecutor:
        """General-purpose I/O pool (the shared pool singleton)."""
        return get_shared_executor()

    @property
    def tool_pool(self) -> concurrent.futures.ThreadPoolExecutor:
        """Tool execution pool for blocking subprocess calls."""
        if self._tool_pool is None:
            if _tool_executor_factory is not None:
                self._tool_pool = _tool_executor_factory()
            else:
                logger.warning(
                    "Tool executor factory not registered; falling back to shared pool. "
                    "Call register_tool_executor_factory() at startup."
                )
                self._tool_pool = get_shared_executor()
        return self._tool_pool

    @property
    def cache_pool(self) -> concurrent.futures.ThreadPoolExecutor:
        """Cache operations pool."""
        return get_shared_executor()

    async def run_in_io(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Submit work to the general I/O pool and await the result."""
        return await run_in_shared_executor(fn, *args, **kwargs)

    def stats(self) -> dict[str, Any]:
        """Return diagnostics for all pools."""
        return {
            "io_pool": shared_pool_stats(),
            "tool_pool": {
                "max_workers": self.tool_pool._max_workers if self._tool_pool else None,
            },
        }


_instance: ExecutionService | None = None


def get_execution_service() -> ExecutionService:
    """Return the process-wide ExecutionService singleton."""
    global _instance
    if _instance is None:
        _instance = ExecutionService()
    return _instance


__all__ = [
    "ExecutionService",
    "get_execution_service",
    "register_tool_executor_factory",
]
