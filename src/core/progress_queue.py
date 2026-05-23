"""Thread-safe progress event queue with overflow protection."""

import threading
import time
from collections.abc import Callable
from queue import Empty, Full, Queue
from typing import Any


class ProgressQueue:
    """Thread-safe progress event queue with overflow protection."""

    def __init__(self, maxsize: int = 10000) -> None:
        self._queue: Queue[dict[str, Any]] = Queue(maxsize=maxsize)
        self._dropped_count: int = 0
        self._lock = threading.Lock()

    def put(self, event: dict[str, Any], block: bool = False, timeout: float = 0.1) -> bool:
        """Put event into queue. If full, drops oldest event and retries."""
        try:
            self._queue.put(event, block=block, timeout=timeout)
            return True
        except Full:
            with self._lock:
                self._dropped_count += 1
            try:
                self._queue.get_nowait()
                self._queue.put(event, block=False)
                return True
            except Full, Empty:
                return False

    def get(self, timeout: float = 1.0) -> dict[str, Any] | None:
        """Get next event, or None on timeout."""
        try:
            return self._queue.get(timeout=timeout)
        except Empty:
            return None

    @property
    def dropped_count(self) -> int:
        with self._lock:
            return self._dropped_count

    @property
    def qsize(self) -> int:
        return self._queue.qsize()


_global_queue: ProgressQueue | None = None
_queue_lock = threading.Lock()


def get_progress_queue() -> ProgressQueue:
    """Return the global singleton ProgressQueue."""
    global _global_queue
    with _queue_lock:
        if _global_queue is None:
            _global_queue = ProgressQueue()
    return _global_queue


def reset_progress_queue() -> None:
    """Reset the global queue (primarily for testing)."""
    global _global_queue
    with _queue_lock:
        _global_queue = None


def create_progress_callback(job_id: str) -> Callable[[dict[str, Any]], None]:
    """Create a thread-safe progress callback for a specific job."""
    queue = get_progress_queue()

    def callback(event: dict[str, Any]) -> None:
        event["job_id"] = job_id
        event["timestamp"] = time.time()
        queue.put(event)

    return callback
