"""
Cyber Security Test Pipeline - Neural-Mesh Ring Event Bus
Implements a high-throughput, no-allocation event plane for frontier security operations.
"""

from __future__ import annotations

import asyncio
import msgpack
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

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

        # Shared Memory Zero-Copy Router
        self._enable_shm = enable_shm
        self._shm_router = None
        if enable_shm:
            try:
                from src.core.frontier.shared_memory import ZeroCopyRouter
                self._shm_router = ZeroCopyRouter()
            except Exception as e:
                logger.warning("Shared memory router initialization failed: %s", e)
                self._enable_shm = False

    def subscribe(self, event_type: str, callback: Callable[[NeuralEvent], Any]) -> None:
        """Subscribe a handler to an event type. '*' for all events."""
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
                    # Offload data to shared memory for large payloads
                    payload = msgpack.packb(data)
                    has_pending_shm = any(event.shm_ref for event in self._buffer)
                    if len(payload) > 1024 and not has_pending_shm: # Only offload if > 1KB
                        shm_ref = self._shm_router.route_payload(payload)
                        data = {"_shm": True} # Placeholder for small in-memory state
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
                            task = asyncio.create_task(handler(event))
                            self._pending_tasks.add(task)
                            task.add_done_callback(self._pending_tasks.discard)
                            # Add callback for error logging in fire-and-forget tasks
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
                            task = asyncio.create_task(handler(event))
                            self._pending_tasks.add(task)
                            task.add_done_callback(self._pending_tasks.discard)
                            task.add_done_callback(self._handle_task_result)
                        else:
                            handler(event)
                    except Exception as e:
                        logger.error("Bus handler failure in shutdown: %s", e)

        # Wait for all pending async task handlers to finish
        if self._pending_tasks:
            await asyncio.gather(*self._pending_tasks, return_exceptions=True)

    def _handle_task_result(self, task: asyncio.Task) -> None:
        """Handle exceptions in fire-and-forget tasks."""
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Bus async handler task failed: %s", e)

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
