"""Single-node asyncio task pool, filesystem run lock, and mesh compatibility shim."""

from __future__ import annotations

import asyncio
import enum
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Coroutine

_CACHE_DIR = Path.home() / ".cache" / "pipeline" / "run_lock"


class NodeRole(enum.Enum):
    """Replaces the mesh consensus leader/follower concept for single-node mode."""

    PRIMARY = "PRIMARY"
    NO_OP = "NO_OP"


class SimpleTaskPool:
    """Single-node asyncio task pool backed by an :class:`asyncio.Queue`."""

    def __init__(self, max_workers: int = 0) -> None:
        self._queue: asyncio.Queue[tuple[int, asyncio.Task]] = asyncio.Queue()
        self._max_workers = max_workers
        self._active_tasks: set[asyncio.Task] = set()
        self._running = False
        self._dispatcher: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    @property
    def worker_count(self) -> int:
        return self._max_workers

    @property
    def active_task_count(self) -> int:
        return len(self._active_tasks)

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._dispatcher = asyncio.ensure_future(self._dispatcher_loop())

    async def submit(self, coroutine: Coroutine, priority: int = 0) -> asyncio.Task:
        """Schedule *coroutine* with an optional priority (higher runs first)."""
        if not self._running:
            raise RuntimeError("SimpleTaskPool is not running. Call start() first.")
        await self._queue.put((priority, asyncio.ensure_future(coroutine)))
        return self._queue.queue[-1][1]

    async def shutdown(self) -> None:
        """Cancel pending tasks and wait for the queue to drain."""
        self._running = False
        if self._dispatcher:
            self._dispatcher.cancel()
            try:
                await self._dispatcher
            except asyncio.CancelledError:
                pass
        async with self._lock:
            while not self._queue.empty():
                _priority, task = self._queue.get_nowait()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)

    async def _dispatcher_loop(self) -> None:
        while self._running:
            priority, task = await self._queue.get()
            async with self._lock:
                self._active_tasks.add(task)
            task.add_done_callback(lambda _: self._active_tasks.discard(task))
            task.add_done_callback(lambda _: self._queue.task_done())


class RunLock:
    """Filesystem-based run lock that prevents concurrent scans of the same target."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._cache_dir = cache_dir or _CACHE_DIR
        self._lock_file: Path | None = None
        self._file_handle: int | None = None
        self._acquired = False
        self._thread_lock = threading.Lock()

    def acquire(self, scan_id: str) -> bool:
        """Attempt to acquire an exclusive lock for *scan_id*. Returns ``True`` on success."""
        with self._thread_lock:
            if self._acquired:
                raise RuntimeError("RunLock is already acquired. Call release() first.")
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            self._lock_file = self._cache_dir / f"{scan_id}.lock"
            try:
                self._file_handle = os.open(str(self._lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self._file_handle, scan_id.encode())
                self._acquired = True
                return True
            except FileExistsError:
                self._file_handle = None
                self._lock_file = None
                return False

    def release(self) -> None:
        """Release a previously acquired lock."""
        with self._thread_lock:
            if not self._acquired:
                return
            if self._file_handle is not None:
                try:
                    os.close(self._file_handle)
                except OSError:
                    pass
                self._file_handle = None
            if self._lock_file and self._lock_file.exists():
                try:
                    self._lock_file.unlink()
                except OSError:
                    pass
            self._lock_file = None
            self._acquired = False

    def __enter__(self) -> RunLock:
        scan_id = getattr(self, "_context_scan_id", "")
        acquired = self.acquire(scan_id)
        if not acquired:
            raise RuntimeError(f"Failed to acquire run lock for scan_id={scan_id!r}")
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()

    def __del__(self) -> None:
        self.release()


class MeshShim:
    """Drop-in replacement for the old neural-mesh API surface when running single-node."""

    def __init__(
        self,
        task_pool: SimpleTaskPool | None = None,
        run_lock: RunLock | None = None,
        enable_multi_worker: bool = False,
    ) -> None:
        self._task_pool = task_pool or SimpleTaskPool()
        self._run_lock = run_lock or RunLock()
        self._enable_multi_worker = enable_multi_worker
        self._role = NodeRole.PRIMARY

    @property
    def enable_multi_worker(self) -> bool:
        return self._enable_multi_worker

    @enable_multi_worker.setter
    def enable_multi_worker(self, value: bool) -> None:
        self._enable_multi_worker = value

    def get_node_role(self) -> NodeRole:
        if self._enable_multi_worker:
            raise NotImplementedError(
                "Multi-worker mode requires the full neural-mesh subsystem "
                "(Raft-lite leader election, gossip protocol, and Redis lease). "
                "Set enable_multi_worker=False to use the single-node task pool."
            )
        return self._role

    def acquire_lock(self, scan_id: str) -> bool:
        return self._run_lock.acquire(scan_id)

    def release_lock(self) -> None:
        self._run_lock.release()

    def get_shard_for_target(self, target: str) -> str:
        return "0"

    async def submit_task(self, coroutine: Coroutine, priority: int = 0) -> asyncio.Task:
        return await self._task_pool.submit(coroutine, priority=priority)

    @property
    def worker_count(self) -> int:
        return self._task_pool.worker_count

    @property
    def active_task_count(self) -> int:
        return self._task_pool.active_task_count
