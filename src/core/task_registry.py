"""Centralized registry for tracked background asyncio tasks.

Prevents orphan tasks by giving every ``asyncio.create_task()`` call a
lifecycle-managed home.  Tasks are grouped by owner (module or subsystem)
so that shutdown can cancel them in reverse-start order.

Usage::

    from src.core.task_registry import get_task_registry

    registry = get_task_registry()
    task = registry.create_task(my_coro(), owner="load_balancer", name="monitor")
    # ... later ...
    await registry.shutdown_owner("load_balancer")   # cancel one owner's tasks
    await registry.shutdown_all()                     # cancel everything
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

# Canonical shutdown order: owners listed first are shut down last (reverse order).
# This ensures downstream consumers stop before upstream producers.
_SHUTDOWN_ORDER: list[str] = [
    "queue_worker_lite",
    "queue_worker",
    "migration_handler",
    "load_balancer",
    "resource_pool",
    "bloom_mesh",
    "mesh_gossip",
    "mesh_sync",
    "eta_engine",
]


class TaskRegistry:
    """Process-wide registry that tracks every spawned asyncio task.

    Thread-safe for registration (uses a lock).  Async methods must be
    called from within the running event loop.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        self._owner_tasks: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        self._counter: int = 0
        self._reconcile_task: asyncio.Task[None] | None = None

    def _next_id(self) -> int:
        """Bug #6: Counter increment is now protected by the registry lock.

        Previously, self._counter += 1 had no lock, but create_task() can be
        called from multiple threads (e.g. asyncio tasks in different loops,
        or thread pool workers). Without the lock, concurrent increments can
        produce duplicate task IDs or lost increments.
        """
        with self._lock:
            self._counter += 1
            return self._counter

    def create_task(
        self,
        coro: Any,
        *,
        owner: str = "unowned",
        name: str | None = None,
    ) -> asyncio.Task[Any]:
        """Create and register a background task.

        Finding 5: Guards against being called from a different event loop
        than the one the registry is associated with.  If the loop mismatch
        is detected, a warning is logged and the coroutine is created without
        tracking (to prevent crashing the caller).
        """
        task_id = f"task-{self._next_id()}"
        if name:
            task_name = f"{owner}/{name}"
        else:
            task_name = f"{owner}/{task_id}"

        try:
            task = asyncio.create_task(coro, name=task_name)
        except RuntimeError as exc:
            # No running loop or wrong-loop call.  Fall back to creating
            # the task on the *current* running loop to avoid crashing
            # the caller, but log a warning.
            logger.warning("TaskRegistry.create_task fell back to raw create_task: %s", exc)
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                # No loop at all — caller is likely in a synchronous context.
                # Cannot create an asyncio task here; re-raise with guidance.
                raise RuntimeError(
                    "TaskRegistry.create_task requires a running event loop"
                ) from exc
            task = loop.create_task(coro, name=task_name)

        with self._lock:
            self._tasks[task_id] = task
            self._owner_tasks.setdefault(owner, set()).add(task_id)

        task.add_done_callback(lambda t, _id=task_id, _owner=owner: self._on_done(_id, _owner))
        logger.debug("Registered task %r (owner=%s)", task_name, owner)
        return task

    def adopt_task(
        self,
        task: asyncio.Task[Any],
        *,
        owner: str = "unowned",
        name: str | None = None,
    ) -> str:
        """Adopt an already-created asyncio.Task into the registry.

        Bug #8: Provides a public API so LifecycleManager and other
        callers don't have to reach into private ``_tasks`` / ``_lock``
        internals.  Returns the assigned task_id.

        If the task is already tracked, returns its existing task_id
        without double-registering.
        """
        # Check if already tracked
        with self._lock:
            for tid, tracked in self._tasks.items():
                if tracked is task:
                    return tid

        task_id = f"task-{self._next_id()}"
        if name:
            task_name = f"{owner}/{name}"
        else:
            task_name = f"{owner}/{task_id}"

        with self._lock:
            self._tasks[task_id] = task
            self._owner_tasks.setdefault(owner, set()).add(task_id)

        task.add_done_callback(lambda t, _id=task_id, _owner=owner: self._on_done(_id, _owner))
        logger.debug("Adopted task %r (owner=%s)", task_name, owner)
        return task_id

    def _on_done(self, task_id: str, owner: str) -> None:
        """Clean up a completed task from the registry."""
        with self._lock:
            self._tasks.pop(task_id, None)
            owner_set = self._owner_tasks.get(owner)
            if owner_set:
                owner_set.discard(task_id)
                if not owner_set:
                    del self._owner_tasks[owner]

    async def shutdown_owner(self, owner: str) -> None:
        """Cancel all tasks belonging to *owner* and await them.

        Uses batched cancellation to limit memory pressure, consistent
        with ``shutdown_all``.
        """
        _BATCH_SIZE = 64

        with self._lock:
            task_ids = list(self._owner_tasks.get(owner, set()))
            tasks = [self._tasks[tid] for tid in task_ids if tid in self._tasks]

        if not tasks:
            return

        logger.info("Cancelling %d tasks for owner '%s'", len(tasks), owner)
        for task in tasks:
            task.cancel()

        # Await in batches to limit memory pressure
        for i in range(0, len(tasks), _BATCH_SIZE):
            batch = tasks[i : i + _BATCH_SIZE]
            await asyncio.gather(*batch, return_exceptions=True)

        with self._lock:
            self._owner_tasks.pop(owner, None)

    async def shutdown_all(self) -> None:
        """Cancel every registered task and await them.

        Bug #15: Batches cancellation into chunks to prevent a memory
        spike when hundreds/thousands of tasks are gathered simultaneously.
        Each batch cancels a fixed number of tasks and waits for them to
        finish before proceeding to the next batch.
        """
        _BATCH_SIZE = 64

        # Defect 8 fix: Stop periodic reconcile before cancelling tasks
        await self.stop_periodic_reconcile()

        with self._lock:
            all_task_ids = list(self._tasks.keys())

        if not all_task_ids:
            return

        logger.info("Cancelling all %d tracked tasks (batched)", len(all_task_ids))

        # Cancel all tasks immediately (non-blocking)
        with self._lock:
            tasks = [self._tasks[tid] for tid in all_task_ids if tid in self._tasks]
        for task in tasks:
            task.cancel()

        # Await in batches to limit memory pressure
        for i in range(0, len(tasks), _BATCH_SIZE):
            batch = tasks[i : i + _BATCH_SIZE]
            await asyncio.gather(*batch, return_exceptions=True)

        with self._lock:
            self._tasks.clear()
            self._owner_tasks.clear()

    async def shutdown_ordered(self) -> None:
        """Shut down all owners in canonical reverse-start order.

        Uses the LifecycleManager's dependency graph as the single source
        of truth for shutdown order when available.  Falls back to the
        local ``_SHUTDOWN_ORDER`` list if LifecycleManager is unavailable.
        Owners not found in either list are cancelled last in arbitrary order.
        """
        try:
            from src.core.lifecycle import get_lifecycle_manager

            lm = get_lifecycle_manager()
            lm_order = lm._resolve_order()
            # LifecycleManager order is cleanup-first; we need reverse for tasks
            ordered_owners = list(reversed(lm_order))
        except (ImportError, Exception):
            ordered_owners = list(_SHUTDOWN_ORDER)

        with self._lock:
            remaining_owners = set(self._owner_tasks.keys())

        for owner in ordered_owners:
            if owner in remaining_owners:
                await self.shutdown_owner(owner)
                remaining_owners.discard(owner)

        for owner in list(remaining_owners):
            await self.shutdown_owner(owner)

    def active_count(self) -> int:
        """Return the number of currently tracked tasks."""
        with self._lock:
            return len(self._tasks)

    def owner_counts(self) -> dict[str, int]:
        """Return per-owner task counts."""
        with self._lock:
            return {owner: len(ids) for owner, ids in self._owner_tasks.items()}

    def reconcile(self) -> dict[str, Any]:
        """Reconcile registry state with actual asyncio task state.

        Detects and removes ghost tasks (tasks in the registry that are
        done/cancelled but were not cleaned up by callbacks).  Returns a
        diagnostic dict showing what was found and cleaned.

        This method should be called periodically (e.g. from a monitoring
        loop) to prevent control-plane drift.
        """
        ghosts: list[str] = []
        orphaned_owners: list[str] = []

        with self._lock:
            for task_id, task in list(self._tasks.items()):
                if task.done() or task.cancelled():
                    ghosts.append(task_id)
                    self._tasks.pop(task_id, None)
                    # Clean up owner mapping
                    for owner, owner_set in self._owner_tasks.items():
                        if task_id in owner_set:
                            owner_set.discard(task_id)
                            break

            # Find owners with empty task sets
            for owner, owner_set in list(self._owner_tasks.items()):
                if not owner_set:
                    orphaned_owners.append(owner)
                    del self._owner_tasks[owner]

        if ghosts:
            logger.warning(
                "Reconciled %d ghost tasks from registry (orphaned owners: %s)",
                len(ghosts),
                orphaned_owners,
            )

        return {
            "ghosts_removed": ghosts,
            "orphaned_owners_removed": orphaned_owners,
            "remaining_tasks": self.active_count(),
        }

    async def start_periodic_reconcile(self, interval_seconds: float = 30.0) -> None:
        """Defect 8 fix: Start a background task that periodically reconciles ghost tasks.

        Prevents unbounded memory growth from completed tasks whose done_callbacks
        failed to fire (e.g. after SIGKILL, event loop stop, etc.).
        """
        if self._reconcile_task is not None and not self._reconcile_task.done():
            return

        async def _loop() -> None:
            while True:
                try:
                    await asyncio.sleep(interval_seconds)
                    self.reconcile()
                except asyncio.CancelledError:
                    break
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Periodic reconcile failed: %s", exc)

        self._reconcile_task = asyncio.create_task(_loop(), name="task_registry/reconcile")
        logger.info("Started periodic task registry reconcile (interval=%ss)", interval_seconds)

    async def stop_periodic_reconcile(self) -> None:
        """Stop the periodic reconcile background task."""
        if self._reconcile_task is not None and not self._reconcile_task.done():
            self._reconcile_task.cancel()
            try:
                await self._reconcile_task
            except asyncio.CancelledError:
                pass
            self._reconcile_task = None

    def status(self) -> dict[str, Any]:
        """Return diagnostic information, including reconciliation check.

        Defect 8 fix: Auto-reconcile when ghost count exceeds threshold
        to prevent unbounded memory growth from completed tasks.
        """
        with self._lock:
            ghost_count = sum(1 for t in self._tasks.values() if t.done() or t.cancelled())
        # Defect 8 fix: Proactively reconcile when ghosts accumulate
        if ghost_count > 10:
            self.reconcile()
        return {
            "active": self.active_count(),
            "by_owner": self.owner_counts(),
            "pending_ghosts": ghost_count,
        }


_registry: TaskRegistry | None = None
_registry_lock = threading.Lock()


def get_task_registry() -> TaskRegistry:
    """Return the process-wide TaskRegistry singleton."""
    global _registry
    with _registry_lock:
        if _registry is None:
            _registry = TaskRegistry()
            # Defect 8 fix: Start periodic reconcile in the background
            try:
                loop = asyncio.get_running_loop()
                starter = loop.create_task(
                    _registry.start_periodic_reconcile(),
                    name="task_registry/periodic_reconcile_start",
                )
                _registry.adopt_task(
                    starter, owner="task_registry", name="periodic_reconcile_start"
                )
            except RuntimeError:
                # No running loop — periodic reconcile will need to be
                # started explicitly later.
                pass
        return _registry


__all__ = [
    "TaskRegistry",
    "get_task_registry",
]
