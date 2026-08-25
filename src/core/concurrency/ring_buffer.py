"""High-Throughput Lock-Free Ring Buffer (LMAX Disruptor Pattern).

Sequential circular buffer with power-of-two capacity for high-velocity target
ingestion and zero-allocation batch consumption.
"""

from __future__ import annotations

import threading
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class DisruptorRingBuffer(Generic[T]):  # noqa: UP046
    """Lock-free style high-throughput ring buffer with sequence barriers."""

    def __init__(self, capacity_exponent: int = 16) -> None:
        # Capacity must be a power of 2 for fast bitwise masking: index = cursor & mask
        self.capacity: int = 1 << capacity_exponent
        self._mask: int = self.capacity - 1
        self._buffer: list[Any] = [None] * self.capacity
        self._write_cursor: int = 0
        self._read_cursor: int = 0
        self._lock = threading.Lock()

    def offer(self, item: T) -> bool:
        """Insert item into ring buffer. Returns False if buffer is full."""
        with self._lock:
            if self._write_cursor - self._read_cursor >= self.capacity:
                return False
            idx = self._write_cursor & self._mask
            self._buffer[idx] = item
            self._write_cursor += 1
            return True

    def drain_batch(self, max_items: int = 128) -> list[T]:
        """Drain a batch of available items in a single slice."""
        with self._lock:
            available = self._write_cursor - self._read_cursor
            if available <= 0:
                return []
            count = min(available, max_items)
            batch = []
            for _ in range(count):
                idx = self._read_cursor & self._mask
                item = self._buffer[idx]
                self._buffer[idx] = None  # Allow GC
                batch.append(item)
                self._read_cursor += 1
            return batch

    def size(self) -> int:
        with self._lock:
            return self._write_cursor - self._read_cursor

    def is_empty(self) -> bool:
        return self.size() == 0


__all__ = ["DisruptorRingBuffer"]
