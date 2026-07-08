"""Shared ThreadPoolExecutor singleton for the entire pipeline.

Eliminates thread proliferation from 25+ independent ThreadPoolExecutor
instances across the codebase. All I/O-bound work should use this shared
pool via get_shared_executor() or run_in_shared_executor().

Usage:
    from src.infrastructure.execution_engine.shared_pool import (
        get_shared_executor,
        run_in_shared_executor,
    )

    # Direct access
    executor = get_shared_executor()
    future = executor.submit(my_fn, arg1, arg2)

    # Helper for async contexts
    result = await run_in_shared_executor(my_fn, arg1, arg2)
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

_DEFAULT_MAX_WORKERS = 16
_pool: ThreadPoolExecutor | None = None
_pool_lock = threading.Lock()

# Dedicated recon pool — isolates recon I/O from general pipeline work
_recon_pool: ThreadPoolExecutor | None = None
_recon_pool_lock = threading.Lock()
_DEFAULT_RECON_WORKERS = 12


def _resolve_max_workers() -> int:
    """Resolve shared pool size from environment or default."""
    try:
        return max(4, int(os.environ.get("SHARED_THREAD_POOL_SIZE", str(_DEFAULT_MAX_WORKERS))))
    except (TypeError, ValueError):
        return _DEFAULT_MAX_WORKERS


def _resolve_recon_workers() -> int:
    """Resolve dedicated recon pool size from environment or default."""
    try:
        return max(4, int(os.environ.get("RECON_THREAD_POOL_SIZE", str(_DEFAULT_RECON_WORKERS))))
    except (TypeError, ValueError):
        return _DEFAULT_RECON_WORKERS


def get_shared_executor() -> ThreadPoolExecutor:
    """Return the process-wide shared ThreadPoolExecutor.

    Thread-safe lazy initialization. Pool size is configured via
    SHARED_THREAD_POOL_SIZE env var (default 16).
    """
    global _pool
    if _pool is not None:
        return _pool

    with _pool_lock:
        if _pool is not None:
            return _pool
        max_workers = _resolve_max_workers()
        _pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="shared-pool",
        )
        logger.debug("Created shared ThreadPoolExecutor with %d workers", max_workers)
        return _pool


def get_recon_executor() -> ThreadPoolExecutor:
    """Return a dedicated ThreadPoolExecutor for recon I/O work.

    Isolates recon tool execution (subfinder, httpx, katana, wayback, etc.)
    from general pipeline I/O to prevent starvation and resource contention.
    """
    global _recon_pool
    if _recon_pool is not None:
        return _recon_pool

    with _recon_pool_lock:
        if _recon_pool is not None:
            return _recon_pool
        max_workers = _resolve_recon_workers()
        _recon_pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="recon-pool",
        )
        logger.debug("Created dedicated recon ThreadPoolExecutor with %d workers", max_workers)
        return _recon_pool


def _cleanup_shared_executor() -> None:
    """Gracefully shut down the shared pool at process exit."""
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.shutdown(wait=True)
            _pool = None


def _cleanup_recon_executor() -> None:
    """Gracefully shut down the recon pool at process exit."""
    global _recon_pool
    with _recon_pool_lock:
        if _recon_pool is not None:
            _recon_pool.shutdown(wait=True)
            _recon_pool = None


def _register_with_lifecycle() -> None:
    try:
        from src.core.lifecycle import get_lifecycle_manager

        mgr = get_lifecycle_manager()
        mgr.register_shutdown(
            "shared_pool",
            _cleanup_shared_executor,
            after=["tool_executor"],
        )
        mgr.register_shutdown(
            "recon_pool",
            _cleanup_recon_executor,
            after=["tool_executor"],
        )
    except ImportError:
        pass


_register_with_lifecycle()


def run_in_shared_executor(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Submit a function to the shared pool and return an awaitable Future.

    Bridges sync I/O work into async contexts via the shared pool,
    avoiding creating new ThreadPoolExecutor instances per call.
    """
    loop = asyncio.get_running_loop()
    executor = get_shared_executor()
    return loop.run_in_executor(executor, lambda: fn(*args, **kwargs))


def submit_to_shared(fn: Any, *args: Any, **kwargs: Any) -> Future[Any]:
    """Submit a function to the shared pool and return a concurrent.futures.Future."""
    executor = get_shared_executor()
    return executor.submit(fn, *args, **kwargs)


def shared_pool_stats() -> dict[str, Any]:
    """Return diagnostics about the shared pool."""
    executor = get_shared_executor()
    return {
        "max_workers": executor._max_workers,
        "pool_exists": _pool is not None,
        "recon_pool_exists": _recon_pool is not None,
        "recon_max_workers": _recon_pool._max_workers if _recon_pool else None,
    }


__all__ = [
    "get_shared_executor",
    "get_recon_executor",
    "run_in_shared_executor",
    "submit_to_shared",
    "shared_pool_stats",
]
