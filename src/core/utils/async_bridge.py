"""Shared utilities for bridging async code into sync contexts.

Centralizes event loop ownership to prevent cross-loop Future attachment
(Bug #22). All subsystems that need to run async code from sync contexts
should use this module rather than creating their own event loops.

Architecture:
  - A single "main loop" is registered when the FastAPI lifespan starts
  - Sync-to-async bridges use the registered loop when available
  - If no loop is registered, a temporary loop is created in a thread
  - Subsystems must NEVER create their own loops for shared objects
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Centralized event loop registry (Bug #22 fix)
# ---------------------------------------------------------------------------

_main_loop: asyncio.AbstractEventLoop | None = None
_main_loop_lock = threading.Lock()


def register_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Register the primary event loop (called at FastAPI lifespan start).

    This is the ONLY loop that should be used for shared objects like
    HTTP clients, Redis connections, and background tasks.
    """
    global _main_loop
    with _main_loop_lock:
        if _main_loop is not None and _main_loop is not loop:
            logger.warning(
                "Replacing previously registered main loop %s with %s",
                id(_main_loop),
                id(loop),
            )
        _main_loop = loop


def get_main_loop() -> asyncio.AbstractEventLoop | None:
    """Return the registered main event loop, or None if not registered."""
    return _main_loop


def reset_main_loop() -> None:
    """Unregister the main loop (called during shutdown)."""
    global _main_loop
    with _main_loop_lock:
        _main_loop = None


# ---------------------------------------------------------------------------
# Shared bridge executor (for cross-thread async-to-sync bridging)
# ---------------------------------------------------------------------------

_bridge_executor: concurrent.futures.ThreadPoolExecutor | None = None
_bridge_lock = threading.Lock()


def _get_bridge_executor() -> concurrent.futures.ThreadPoolExecutor:
    """Return a shared executor for async-to-sync bridging."""
    global _bridge_executor
    if _bridge_executor is not None:
        return _bridge_executor
    with _bridge_lock:
        if _bridge_executor is not None:
            return _bridge_executor
        _bridge_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="async-bridge"
        )
        return _bridge_executor


def run_async_in_sync_context(coro: Any) -> Any:
    """Run an async coroutine from sync code when an event loop is already running.

    Strategy (in order of preference):
    1. If a registered main loop exists and is running, schedule on it
       (thread-safe via run_coroutine_threadsafe).
    2. If no loop is running, use asyncio.run() directly.
    3. Only as a last resort, create a temporary loop in a background
       thread — this is the legacy path and should be eliminated over time.

    Creating temporary loops risks cross-loop Future attachment, so we
    log a warning whenever the fallback path is taken.
    """
    # Try the registered main loop first (preferred path)
    result = run_on_main_loop_sync(coro, timeout=30.0)
    if result is not None:
        return result

    # No main loop available — check if we're outside any event loop
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No loop running at all — safe to use asyncio.run()
        return asyncio.run(coro)

    # A loop is running but it's not ours (or isn't registered).
    # Last resort: temporary loop in a thread.  Log so we can track
    # and eventually eliminate these call sites.
    logger.warning(
        "run_async_in_sync_context: falling back to temporary event loop. "
        "This risks cross-loop Future attachment. "
        "Migrate caller to use schedule_on_main_loop() instead."
    )

    def _run_in_thread() -> Any:
        new_loop = asyncio.new_event_loop()
        try:
            return new_loop.run_until_complete(coro)
        finally:
            new_loop.close()

    future = _get_bridge_executor().submit(_run_in_thread)
    return future.result()


def schedule_on_main_loop(coro: Any) -> asyncio.Task | None:
    """Schedule a coroutine on the registered main loop.

    Returns the Task if successful, None if no loop is available.
    This is the preferred way for sync code to trigger async work
    without creating a new loop.
    """
    loop = _main_loop
    if loop is None or loop.is_closed():
        return None
    if loop.is_running():
        return loop.create_task(coro)
    return None


def run_on_main_loop_sync(coro: Any, timeout: float = 5.0) -> Any:
    """Run a coroutine on the main loop from a sync thread.

    Uses run_coroutine_threadsafe with a bounded timeout.
    Returns None on timeout or if no loop is available.
    """
    loop = _main_loop
    if loop is None or loop.is_closed():
        return None
    if not loop.is_running():
        # Loop exists but isn't running — can run directly
        return loop.run_until_complete(coro)
    # Loop is running on another thread — use thread-safe submission
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return future.result(timeout=timeout)
    except TimeoutError:
        logger.debug("run_on_main_loop_sync timed out after %.1fs", timeout)
        return None
    except Exception as exc:
        logger.debug("run_on_main_loop_sync failed: %s", exc)
        return None
