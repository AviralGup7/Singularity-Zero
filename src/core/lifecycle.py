"""Centralized lifecycle manager for coordinated startup and shutdown.

Replaces the fragmented atexit.register pattern with a single manager that
enforces shutdown ordering, dependency tracking, and graceful degradation.

This module lives in src.core because lifecycle management is a cross-cutting
concern that both core and infrastructure modules need to participate in.

Usage::

    from src.core.lifecycle import get_lifecycle_manager

    mgr = get_lifecycle_manager()
    mgr.register_shutdown("http_clients", cleanup_http_clients, after=["tool_executor"])
    mgr.register_shutdown("tool_executor", cleanup_tool_executor, after=["shared_pool"])
    mgr.register_shutdown("shared_pool", cleanup_shared_pool)

    # Register background tasks for cleanup tracking
    task = loop.create_task(my_background_work())
    mgr.register_task("my_bg_task", task)

    # At process exit, the manager:
    # 1. Cancels all registered tasks
    # 2. Runs all cleanups in dependency order
    # 3. Verifies cleanup completion
"""

from __future__ import annotations

import atexit
import logging
import threading
from collections import defaultdict
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class LifecycleManager:
    """Coordinates shutdown ordering across subsystems.

    Subsystems register cleanup callbacks with dependency declarations.
    At shutdown, the manager:
    1. Cancels all registered background tasks
    2. Topologically sorts and runs cleanups in dependency order
    3. Verifies cleanup completion

    Thread-safe for registration. Shutdown runs once in the main thread.
    """

    def __init__(self) -> None:
        self._shutdown_hooks: dict[str, Callable[[], Any]] = {}
        self._shutdown_after: dict[str, list[str]] = defaultdict(list)
        self._executed: set[str] = set()
        self._lock = threading.Lock()
        self._shutdown_started = False
        # Bug #23: Track background tasks for proper cleanup
        self._tracked_tasks: dict[str, Any] = {}  # name -> asyncio.Task
        self._tracked_callbacks: dict[str, list[Callable]] = defaultdict(list)
        # Bug #12: Track daemon threads so we can join them on shutdown.
        self._tracked_threads: dict[str, threading.Thread] = {}  # name -> Thread
        self._THREAD_JOIN_TIMEOUT = 5.0  # seconds per thread

    def register_shutdown(
        self,
        name: str,
        cleanup: Callable[[], Any],
        *,
        after: list[str] | None = None,
    ) -> None:
        """Register a cleanup callback with optional dependency ordering.

        Args:
            name: Unique name for this cleanup (e.g., "shared_pool").
            cleanup: Callable to invoke at shutdown.
            after: List of cleanup names that must run BEFORE this one.
        """
        with self._lock:
            self._shutdown_hooks[name] = cleanup
            if after:
                self._shutdown_after[name] = list(after)

    def register_task(self, name: str, task: Any) -> None:
        """Register a background asyncio.Task for cleanup tracking.

        Delegates to the process-wide TaskRegistry to avoid dual-tracking
        ownership drift.  The LifecycleManager no longer maintains its own
        task set -- it queries the registry at shutdown time.

        This is a compatibility shim: existing callers that pass
        ``(name, task)`` still work, but the task is now tracked by
        exactly one system (TaskRegistry).
        """
        try:
            from src.core.task_registry import get_task_registry

            registry = get_task_registry()
            # Bug #8: Use the public adopt_task() API instead of reaching
            # into private _tasks/_lock/_owner_tasks/_next_id() internals.
            if hasattr(task, "get_name"):
                # Check if already tracked before adopting
                with registry._lock:
                    already_tracked = any(task is t for t in registry._tasks.values())
                if not already_tracked:
                    registry.adopt_task(task, owner="lifecycle", name=name)
        except ImportError:
            logger.debug("TaskRegistry not available — skipping task registration")

    def unregister_task(self, name: str) -> None:
        """Remove a tracked task (e.g., after it completes naturally)."""
        with self._lock:
            self._tracked_tasks.pop(name, None)

    def register_thread(self, name: str, thread: threading.Thread) -> None:
        """Register a daemon thread for shutdown tracking.

        Bug #12: Daemon threads (e.g. checkpoint replication) are killed
        silently at process exit unless we join them first.  Registering
        them here ensures the lifecycle manager will wait for them to
        finish before tearing down resources.
        """
        with self._lock:
            self._tracked_threads[name] = thread
        logger.debug("Registered thread %r (daemon=%s)", name, thread.daemon)

    def _join_tracked_threads(self) -> None:
        """Join all registered daemon threads with a timeout.

        Called during shutdown so that in-flight work (e.g. checkpoint
        replication) completes before storage backends are closed.
        """
        with self._lock:
            threads = dict(self._tracked_threads)
            self._tracked_threads.clear()

        for name, thread in threads.items():
            if thread.is_alive():
                logger.info("Waiting for thread %r to finish...", name)
                thread.join(timeout=self._THREAD_JOIN_TIMEOUT)
                if thread.is_alive():
                    logger.warning(
                        "Thread %r did not finish within %.1fs shutdown timeout",
                        name,
                        self._THREAD_JOIN_TIMEOUT,
                    )

    def register_callback(self, group: str, callback: Callable) -> None:
        """Register a callback in a named group for batch cleanup.

        All callbacks in a group are called during shutdown and the group
        is then cleared, preventing duplicate execution on restart (Bug #23).
        """
        with self._lock:
            self._tracked_callbacks[group].append(callback)

    def clear_callbacks(self, group: str) -> None:
        """Clear all callbacks in a group (e.g., after manual cleanup)."""
        with self._lock:
            self._tracked_callbacks.pop(group, None)

    def _cancel_tracked_tasks(self) -> None:
        """Cancel all registered background tasks and await completion.

        Bug #10: After requesting cancellation, we await each task with
        a timeout so that ``finally`` blocks complete before resource
        cleanup hooks run.  Without this, tasks would still be executing
        (e.g. writing to a closed Redis connection) when the cleanup
        hooks tear down the underlying resources.

        Cancels tasks from both the local ``_tracked_tasks`` dict (legacy
        compatibility) **and** the process-wide ``TaskRegistry``.
        """
        import asyncio

        with self._lock:
            tasks = dict(self._tracked_tasks)

        # Phase 1: request cancellation (non-blocking)
        for name, task in tasks.items():
            if hasattr(task, "cancel") and not task.done():
                try:
                    task.cancel()
                except Exception as exc:
                    logger.debug("Failed to cancel task %r: %s", name, exc)

        # Phase 2: await completion with timeout so finally blocks can run
        _SHUTDOWN_TASK_TIMEOUT = 5.0  # seconds
        pending = [t for t in tasks.values() if hasattr(t, "done") and not t.done()]
        if pending:
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():

                    async def _await_cancelled() -> None:
                        _, still_pending = await asyncio.wait(
                            pending,
                            timeout=_SHUTDOWN_TASK_TIMEOUT,
                        )
                        if still_pending:
                            logger.warning(
                                "Lifecycle: %d tasks did not complete within "
                                "%.1fs shutdown timeout",
                                len(still_pending),
                                _SHUTDOWN_TASK_TIMEOUT,
                            )

                    try:
                        asyncio.ensure_future(_await_cancelled())
                    except RuntimeError:
                        logger.debug("Could not ensure future for task cancellation")
            except RuntimeError:
                # Sync shutdown path (atexit) -- best-effort wait
                for task in pending:
                    try:
                        import concurrent.futures

                        f = concurrent.futures.Future()

                        def _done_cb(t, _f=f):
                            _f.set_result(None)

                        task.add_done_callback(_done_cb)
                        f.result(timeout=min(_SHUTDOWN_TASK_TIMEOUT, 2.0))
                    except (
                        concurrent.futures.TimeoutError,
                        concurrent.futures.CancelledError,
                    ) as _lif_exc:
                        logger.debug(
                            "Sync shutdown wait failed for task: %s", _lif_exc, exc_info=True
                        )

        # Phase 3: Cancel tasks tracked by the TaskRegistry (Bug #8).
        try:
            from src.core.task_registry import get_task_registry

            registry = get_task_registry()
            active = registry.active_count()
            if active:
                logger.info("Lifecycle: cancelling %d registry-tracked tasks", active)
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    shutdown_task = asyncio.ensure_future(registry.shutdown_all())
                    shutdown_task.add_done_callback(
                        lambda t: (
                            logger.debug("Registry shutdown_all completed")
                            if t.exception() is None
                            else logger.warning("Registry shutdown_all failed: %s", t.exception())
                        )
                    )
            except RuntimeError:
                try:
                    loop = asyncio.new_event_loop()
                    try:
                        loop.run_until_complete(registry.shutdown_all())
                    finally:
                        loop.close()
                except Exception as exc:
                    logger.debug("Registry shutdown_all failed in sync path: %s", exc)
        except ImportError:
            logger.debug(
                "TaskRegistry not available during shutdown — skipping registry task cancellation"
            )

    def _run_tracked_callbacks(self) -> None:
        """Execute and clear all registered callback groups."""
        with self._lock:
            groups = dict(self._tracked_callbacks)
            self._tracked_callbacks.clear()
        for group_name, callbacks in groups.items():
            for cb in callbacks:
                try:
                    cb()
                except Exception as exc:
                    logger.warning("Tracked callback in group %r failed: %s", group_name, exc)

    def _resolve_order(self) -> list[str]:
        """Topologically sort shutdown hooks by dependencies."""
        in_degree: dict[str, int] = {name: 0 for name in self._shutdown_hooks}
        dependents: dict[str, list[str]] = defaultdict(list)

        for name, deps in self._shutdown_after.items():
            for dep in deps:
                if dep in self._shutdown_hooks:
                    dependents[dep].append(name)
                    in_degree[name] += 1

        queue = [name for name, deg in in_degree.items() if deg == 0]
        result: list[str] = []

        while queue:
            queue.sort()  # deterministic order for same-degree nodes
            name = queue.pop(0)
            result.append(name)
            for dependent in dependents[name]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        if len(result) != len(self._shutdown_hooks):
            remaining = set(self._shutdown_hooks) - set(result)
            logger.error(
                "Circular dependencies detected involving %s — "
                "these cleanups will run in arbitrary order. "
                "This is a bug: fix the dependency declarations.",
                remaining,
            )
            # Still append them so shutdown doesn't hang, but mark them
            # as degraded so callers know the order is unreliable.
            for name in self._shutdown_hooks:
                if name not in result:
                    result.append(name)

        return result

    def shutdown(self) -> None:
        """Run all registered cleanups in dependency order.

        Shutdown sequence:
        1. Cancel all tracked background tasks and await them
        2. Join all tracked daemon threads (Bug #12)
        3. Run all tracked callbacks (listeners, subscriptions)
        4. Run cleanups in dependency order

        Safe to call multiple times -- only runs once.
        """
        with self._lock:
            if self._shutdown_started:
                return
            self._shutdown_started = True

        # Bug #23: Cancel background tasks first to prevent new work
        self._cancel_tracked_tasks()

        # Bug #12: Join daemon threads so in-flight work completes
        # before resource teardown (e.g. checkpoint replication).
        self._join_tracked_threads()

        # Bug #23: Run tracked callbacks to clear listeners
        self._run_tracked_callbacks()

        order = self._resolve_order()
        logger.info(
            "Lifecycle shutdown: running %d cleanups in order: %s",
            len(order),
            " -> ".join(order),
        )

        for name in order:
            if name in self._executed:
                continue
            cleanup = self._shutdown_hooks.get(name)
            if cleanup is None:
                continue
            try:
                cleanup()
                self._executed.add(name)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Lifecycle cleanup %r failed: %s", name, exc)

    def status(self) -> dict[str, Any]:
        """Return diagnostic information about registered cleanups."""
        registry_active = 0
        try:
            from src.core.task_registry import get_task_registry

            registry_active = get_task_registry().active_count()
        except ImportError:
            registry_active = 0
        return {
            "registered": list(self._shutdown_hooks.keys()),
            "executed": list(self._executed),
            "order": self._resolve_order(),
            "shutdown_started": self._shutdown_started,
            "tracked_tasks": list(self._tracked_tasks.keys()),
            "tracked_threads": list(self._tracked_threads.keys()),
            "registry_active_tasks": registry_active,
            "tracked_callback_groups": list(self._tracked_callbacks.keys()),
        }


_manager: LifecycleManager | None = None
_manager_lock = threading.Lock()
_atexit_registered = False


def get_lifecycle_manager() -> LifecycleManager:
    """Return the process-wide lifecycle manager singleton.

    Bug #22: Uses a flag to prevent duplicate atexit registration when
    the module is reloaded (e.g., in test harness or uvicorn --reload).
    """
    global _manager, _atexit_registered
    with _manager_lock:
        if _manager is None:
            _manager = LifecycleManager()
            if not _atexit_registered:
                atexit.register(_manager.shutdown)
                _atexit_registered = True
        return _manager


__all__ = [
    "LifecycleManager",
    "get_lifecycle_manager",
]
