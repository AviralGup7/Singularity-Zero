from __future__ import annotations

import logging

"""Single-node asyncio task pool, filesystem run lock, and mesh compatibility shim."""


import asyncio
import enum
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

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

    async def submit(self, coroutine: Coroutine, priority: int = 0) -> asyncio.Task[Any]:
        """Schedule *coroutine* with an optional priority (higher runs first)."""
        if not self._running:
            raise RuntimeError("SimpleTaskPool is not running. Call start() first.")
        task = asyncio.ensure_future(coroutine)
        await self._queue.put((priority, task))  # type: ignore[await-not-async]
        return task

    async def shutdown(self) -> None:
        """Cancel pending tasks and wait for the queue to drain."""
        self._running = False
        if self._dispatcher:
            self._dispatcher.cancel()
            try:
                await self._dispatcher
            except asyncio.CancelledError as exc:
                logging.warning("Operation failed in task_pool.py: %s", exc, exc_info=True)  # noqa: BLE001
        async with self._lock:
            while not self._queue.empty():
                _priority, task = self._queue.get_nowait()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError as exc:
                    logging.warning("Operation failed in task_pool.py: %s", exc, exc_info=True)  # noqa: BLE001
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)

    async def _dispatcher_loop(self) -> None:
        while self._running:
            priority, task = await self._queue.get()
            async with self._lock:
                self._active_tasks.add(task)
            task.add_done_callback(lambda _: self._active_tasks.discard(task))
            task.add_done_callback(lambda _: self._queue.task_done())
            await asyncio.sleep(0)


class RunLock:
    """Distributed run lock that prevents concurrent scans of the same target.

    Uses Redis SET NX PX for cross-node locking when Redis is available,
    falling back to filesystem-based locking for single-node deployments.
    """

    REDIS_LOCK_PREFIX = "cyber:run_lock:"

    def __init__(self, cache_dir: Path | None = None, redis_url: str | None = None) -> None:
        self._cache_dir = cache_dir or _CACHE_DIR
        self._lock_file: Path | None = None
        self._file_handle: int | None = None
        self._acquired = False
        self._thread_lock = threading.Lock()
        self._redis_url = redis_url or os.getenv("REDIS_URL")
        self._redis_client: Any = None
        self._lock_key: str | None = None
        self._lock_value: str | None = None

    def _get_redis(self) -> Any:
        """Lazily initialize a Redis client for distributed locking."""
        if self._redis_client is not None:
            return self._redis_client
        if not self._redis_url:
            return None
        try:
            import redis

            self._redis_client = redis.Redis.from_url(
                self._redis_url,
                socket_timeout=5,
                socket_connect_timeout=5,
                decode_responses=True,
            )
            self._redis_client.ping()
            return self._redis_client
        except Exception as exc:
            logging.debug("Redis unavailable for distributed lock, using filesystem: %s", exc)
            self._redis_client = None
            return None

    def acquire(self, scan_id: str, ttl_seconds: int = 3600, owner_id: str | None = None) -> bool:
        """Attempt to acquire an exclusive lock for *scan_id*.

        Tries Redis SET NX PX first (cross-node safe); falls back to
        filesystem if Redis is unavailable.

        Args:
            scan_id: Unique identifier for the scan/run.
            ttl_seconds: Lock expiry in seconds (default 1 hour).
            owner_id: Optional owner identifier (the run ID) to support re-entrancy.

        Returns:
            True on success, False if the lock is already held.
        """
        import uuid

        with self._thread_lock:
            if self._acquired:
                raise RuntimeError("RunLock is already acquired. Call release() first.")

            # Try Redis distributed lock first
            redis = self._get_redis()
            if redis is not None:
                self._lock_key = f"{self.REDIS_LOCK_PREFIX}{scan_id}"
                self._lock_value = owner_id or str(uuid.uuid4())
                try:
                    existing = redis.get(self._lock_key)
                    if existing == self._lock_value:
                        self._acquired = True
                        return True

                    acquired = redis.set(
                        self._lock_key,
                        self._lock_value,
                        nx=True,
                        px=ttl_seconds * 1000,
                    )
                    if acquired:
                        self._acquired = True
                        return True
                    return False
                except Exception as exc:
                    logging.debug("Redis lock acquire failed, falling back to filesystem: %s", exc)

            # Fallback: filesystem lock
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            self._lock_file = self._cache_dir / f"{scan_id}.lock"
            if self._lock_file.exists():
                try:
                    with open(self._lock_file) as f:
                        val = f.read().strip()
                    if owner_id and val == owner_id:
                        self._acquired = True
                        return True
                except Exception:
                    pass
                self._lock_file = None
                return False

            try:
                self._file_handle = os.open(
                    str(self._lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY
                )
                self._lock_value = owner_id or str(uuid.uuid4())
                os.write(self._file_handle, self._lock_value.encode())
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

            # Release Redis lock if held
            if self._lock_key and self._lock_value:
                redis = self._get_redis()
                if redis is not None:
                    try:
                        # Only delete if we own it (compare-and-delete)
                        lua_script = """
                        if redis.call("GET", KEYS[1]) == ARGV[1] then
                            return redis.call("DEL", KEYS[1])
                        else
                            return 0
                        end
                        """
                        redis.eval(lua_script, 1, self._lock_key, self._lock_value)
                    except Exception as exc:
                        logging.debug("Redis lock release failed: %s", exc)
                self._lock_key = None
                self._lock_value = None

            # Release filesystem lock if held
            if self._file_handle is not None:
                try:
                    os.close(self._file_handle)
                except OSError as exc:
                    logging.warning("Operation failed in task_pool.py: %s", exc, exc_info=True)  # noqa: BLE001
                self._file_handle = None
            if self._lock_file and self._lock_file.exists():
                try:
                    self._lock_file.unlink()
                except OSError as exc:
                    logging.warning("Operation failed in task_pool.py: %s", exc, exc_info=True)  # noqa: BLE001
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

    async def submit_task(self, coroutine: Coroutine, priority: int = 0) -> asyncio.Task[Any]:
        task_pool = self._task_pool
        assert task_pool is not None
        return await task_pool.submit(coroutine, priority=priority)

    @property
    def worker_count(self) -> int:
        return self._task_pool.worker_count

    @property
    def active_task_count(self) -> int:
        return self._task_pool.active_task_count
