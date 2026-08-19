"""
Cyber Security Test Pipeline - Neural-Mesh Ring Event Bus
Implements a high-throughput, no-allocation event plane for frontier security operations.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import msgpack

logger = logging.getLogger(__name__)

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


@dataclass
class NeuralEvent:
    """Cyber Pipeline Event Envelope."""

    type: str
    source: str
    data: dict[str, Any]
    priority: int = 0
    shm_ref: str | None = None  # Reference to payload in shared memory


class FrontierRingBus:
    """
    Bounded-buffer event bus.
    Optimized for massive event emission rates with zero heap fragmentation.
    """

    def __init__(self, capacity: int = 10000, enable_shm: bool = False) -> None:
        self._buffer: deque[NeuralEvent] = deque(maxlen=capacity)
        self._subscribers: dict[str, list[Callable[[NeuralEvent], Any]]] = {}
        self._running = False
        self._downsample_threshold = capacity // 2
        import threading

        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wakeup_event = asyncio.Event()
        self._dropped_events = 0
        self._pending_tasks: set[asyncio.Task] = set()
        self._task_semaphore: asyncio.Semaphore | None = None
        self._MAX_CONCURRENT_TASKS = 256
        # Bug #1 fix: Cap pending task creation to prevent unbounded memory growth.
        # The semaphore limits concurrency, but tasks still exist in memory until
        # they finish. Without this cap, 100k events × 100 subscribers = 10M tasks
        # created before any handler finishes.
        self._MAX_PENDING_TASKS = 2048
        self._pending_task_drops = 0

        # Finding 9: Error deduplication — prevents log storms when a
        # handler fails repeatedly with the same error.
        self._consecutive_errors = 0
        self._error_suppress_after = 20  # suppress after N identical errors
        self._last_error_msg: str | None = None

        # Shared Memory Zero-Copy Router
        self._enable_shm = enable_shm
        self._shm_router = None
        self._shm_max_in_flight = max(1, capacity // 10)
        if enable_shm:
            try:
                from src.core.frontier.shared_memory import ZeroCopyRouter

                self._shm_router = ZeroCopyRouter()
            except Exception as e:
                logger.warning("Shared memory router initialization failed: %s", e)
                self._enable_shm = False

    def subscribe(self, event_type: str, callback: Callable[[NeuralEvent], Any]) -> None:
        """Subscribe a handler to an event type. '*' for all events."""
        with self._lock:
            self._subscribers.setdefault(event_type, []).append(callback)

    def emit(self, event_type: str, source: str, data: dict[str, Any], priority: int = 0) -> None:
        """Append event to the ring buffer."""
        # Fix #378: Add thread lock around buffer access
        with self._lock:
            # 1. Adaptive Downsampling Guard
            if len(self._buffer) > self._downsample_threshold and priority < 5:
                # Skip low-priority events during mesh congestion
                self._dropped_events += 1
                logger.warning(
                    "Dropped low-priority event %s from %s due to mesh congestion (dropped=%d)",
                    event_type,
                    source,
                    self._dropped_events,
                )
                return

            shm_ref = None
            if self._enable_shm and self._shm_router:
                try:
                    # Offload data to shared memory for large payloads. Previously
                    # the offload was gated on "no other SHM events pending",
                    # which silently disabled the optimization under load.
                    # The cap is now expressed as a maximum number of in-flight
                    # SHM references so that high-throughput producers continue
                    # to benefit from zero-copy routing.
                    payload = msgpack.packb(data)
                    if len(payload) > 1024:
                        pending_shm = sum(1 for event in self._buffer if event.shm_ref)
                        if pending_shm < self._shm_max_in_flight:
                            shm_ref = self._shm_router.route_payload(payload)
                            data = {"_shm": True}  # Placeholder for small in-memory state
                except Exception as e:
                    logger.debug("SHM offload failed, falling back to in-memory: %s", e)

            event = NeuralEvent(event_type, source, data, priority, shm_ref=shm_ref)
            self._buffer.append(event)

        loop = self._loop
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(self._wakeup_event.set)

    async def start_dispatch_loop(self) -> None:
        """High-speed async dispatcher."""
        self._loop = asyncio.get_running_loop()
        self._running = True
        self._wakeup_event.clear()
        self._task_semaphore = asyncio.Semaphore(self._MAX_CONCURRENT_TASKS)
        logger.info("Neural-Mesh Ring Bus active (Capacity: %d)", self._buffer.maxlen)

        while self._running:
            with self._lock:
                if not self._buffer:
                    events = []
                else:
                    batch_size = min(len(self._buffer), 100)
                    events = [self._buffer.popleft() for _ in range(batch_size)]

            if not events:
                await self._wakeup_event.wait()
                self._wakeup_event.clear()
                continue

            for event in events:
                # 2. Shared Memory Retrieval
                if not self._hydrate_event_payload(event):
                    continue

                # Fix Audit #125: Create a new combined list to avoid mutation during iteration
                specific = self._subscribers.get(event.type, [])
                wildcard = self._subscribers.get("*", [])
                handlers = list(specific) + list(wildcard)

                for handler in handlers:
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            # Bug #1 fix: Backpressure check before creating task.
                            # The semaphore limits concurrent execution, but tasks
                            # still consume memory until they finish.
                            if len(self._pending_tasks) >= self._MAX_PENDING_TASKS:
                                self._pending_task_drops += 1
                                if self._pending_task_drops % 100 == 1:
                                    logger.warning(
                                        "RingBus backpressure: %d tasks pending (max %d). "
                                        "Dropping handler to prevent OOM. total_drops=%d",
                                        len(self._pending_tasks),
                                        self._MAX_PENDING_TASKS,
                                        self._pending_task_drops,
                                    )
                                continue

                            # Bug #8: Check global governor to prevent
                            # multiplicative task explosion across subsystems.
                            # Finding 3: Governor acquire + release wrapped
                            # so the permit is released if create_task fails.
                            _gov = None
                            try:
                                from src.core.concurrency_governor import get_governor

                                _gov = get_governor()
                                if not _gov.allow("ring_bus"):
                                    continue
                            except ImportError:
                                _gov = None

                            try:

                                async def _guarded(h=handler, e=event, sem=self._task_semaphore):
                                    async with sem:
                                        await h(e)

                                task = asyncio.create_task(_guarded())
                            except Exception as exc:
                                # Finding 3: Release the governor permit if
                                # create_task itself fails (e.g. loop closed).
                                if _gov is not None:
                                    try:
                                        _gov.release("ring_bus")
                                    except Exception:
                                        logger.debug("Non-critical cleanup error", exc_info=True)
                                logger.warning("RingBus create_task failed: %s", exc)
                                continue

                            self._pending_tasks.add(task)
                            task.add_done_callback(self._pending_tasks.discard)

                            def _on_done(t: asyncio.Task, gov=_gov) -> None:
                                self._pending_tasks.discard(t)
                                if gov is not None:
                                    try:
                                        gov.release("ring_bus")
                                    except (ImportError, Exception):
                                        pass

                            task.add_done_callback(_on_done)
                            task.add_done_callback(self._handle_task_result)
                        else:
                            handler(event)
                    except Exception as e:
                        logger.error("Bus handler failure: %s", e)

            # Tiny yield to allow event producers to catch up
            await asyncio.sleep(0)

        # Process any remaining events in the buffer after running is set to False
        while True:
            with self._lock:
                if not self._buffer:
                    break
                batch_size = min(len(self._buffer), 100)
                events = [self._buffer.popleft() for _ in range(batch_size)]

            for event in events:
                if not self._hydrate_event_payload(event):
                    continue

                specific = self._subscribers.get(event.type, [])
                wildcard = self._subscribers.get("*", [])
                handlers = list(specific) + list(wildcard)

                for handler in handlers:
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            if len(self._pending_tasks) >= self._MAX_PENDING_TASKS:
                                self._pending_task_drops += 1
                                continue

                            # Bug #9: Apply governor check in shutdown drain
                            # path to prevent invisible task explosion.
                            try:
                                from src.core.concurrency_governor import get_governor

                                if not get_governor().allow("ring_bus"):
                                    self._pending_task_drops += 1
                                    continue
                            except ImportError:
                                pass

                            async def _guarded_shutdown(
                                h=handler, e=event, sem=self._task_semaphore
                            ):
                                async with sem:
                                    await h(e)

                            task = asyncio.create_task(_guarded_shutdown())
                            self._pending_tasks.add(task)
                            task.add_done_callback(self._pending_tasks.discard)

                            def _on_done_shutdown(t: asyncio.Task) -> None:
                                self._pending_tasks.discard(t)
                                try:
                                    from src.core.concurrency_governor import get_governor

                                    get_governor().release("ring_bus")
                                except (ImportError, Exception):
                                    pass

                            task.add_done_callback(_on_done_shutdown)
                            task.add_done_callback(self._handle_task_result)
                        else:
                            # Bug #9: Sync handlers also count toward the
                            # ring_bus subsystem for accurate accounting.
                            try:
                                from src.core.concurrency_governor import get_governor

                                if not get_governor().allow("ring_bus"):
                                    continue
                                try:
                                    handler(event)
                                finally:
                                    get_governor().release("ring_bus")
                            except ImportError:
                                handler(event)
                    except Exception as e:
                        logger.error("Bus handler failure in shutdown: %s", e)

        # Finding 10: Wait for pending task handlers with a timeout to
        # prevent deadlock with TaskRegistry shutdown.  Without this,
        # the drain can hang indefinitely if a task is stuck being
        # cancelled by the registry shutdown sequence.
        if self._pending_tasks:
            _drain_deadline = 10.0  # seconds
            done, pending = await asyncio.wait(
                self._pending_tasks,
                timeout=_drain_deadline,
            )
            if pending:
                logger.warning(
                    "RingBus shutdown drain: %d tasks still pending after %.0fs timeout, "
                    "aborting remaining",
                    len(pending),
                    _drain_deadline,
                )
                for t in pending:
                    t.cancel()

    def _handle_task_result(self, task: asyncio.Task) -> None:
        """Handle exceptions in fire-and-forget tasks with deduplication."""
        try:
            task.result()
            # Success resets the consecutive error counter.
            self._consecutive_errors = 0
            self._last_error_msg = None
        except asyncio.CancelledError as exc:
            logger.warning("Operation failed in ring_bus.py: %s", exc, exc_info=True)  # noqa: BLE001
        except Exception as e:
            # Finding 9: Deduplicate repeated identical errors to
            # prevent log storms.
            self._consecutive_errors += 1
            err_msg = str(e)
            if (
                self._consecutive_errors <= self._error_suppress_after
                or err_msg != self._last_error_msg
            ):
                logger.error("Bus async handler task failed: %s", e)
                self._last_error_msg = err_msg
            elif self._consecutive_errors == self._error_suppress_after + 1:
                logger.error(
                    "Bus async handler task failures continuing "
                    "(suppressed identical messages until pattern changes): "
                    "consecutive=%d last_error=%s",
                    self._consecutive_errors,
                    err_msg,
                )

    def _hydrate_event_payload(self, event: NeuralEvent) -> bool:
        """Load a shared-memory payload back into the event before dispatch."""
        if not event.shm_ref:
            return True
        if not self._shm_router:
            logger.error("Failed to retrieve event data from SHM: router unavailable")
            return False
        try:
            raw_payload = self._shm_router.retrieve_payload(event.shm_ref)
            event.data = msgpack.unpackb(raw_payload, raw=False)
            return True
        except Exception as e:
            logger.error("Failed to retrieve event data from SHM: %s", e)
            return False

    def stop(self) -> None:
        """Gracefully stop the dispatch loop."""
        self._running = False
        loop = self._loop
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(self._wakeup_event.set)

    def get_dropped_events(self) -> int:
        """Return the number of dropped low-priority events during congestion."""
        with self._lock:
            return self._dropped_events
