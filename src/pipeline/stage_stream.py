"""Inter-stage streaming backpressure channel (F-004 / Category 3 Item 10).

Provides bounded asynchronous streaming (StageStream[T]) between producer stages
(e.g., subdomain enumeration, URL collection) and consumer scanning stages,
preventing memory exhaustion and OOM crashes when processing 100,000+ items.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Generic, TypeVar

T = TypeVar("T")

DEFAULT_STREAM_BUFFER_SIZE = 1000


class StageStream(Generic[T]):
    """Bounded asynchronous stream channel with backpressure.
    
    Producers await ``emit(item)`` when the downstream buffer is full.
    Consumers iterate over ``stream`` asynchronously or consume in batches.
    """

    def __init__(self, maxsize: int = DEFAULT_STREAM_BUFFER_SIZE, name: str = "stage_stream") -> None:
        self.maxsize = max(1, maxsize)
        self.name = name
        self._queue: asyncio.Queue[T | object] = asyncio.Queue(maxsize=self.maxsize)
        self._closed = False
        self._sentinel = object()
        self._total_emitted = 0
        self._total_consumed = 0

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def buffer_depth(self) -> int:
        return self._queue.qsize()

    @property
    def stats(self) -> dict[str, int | str]:
        return {
            "name": self.name,
            "maxsize": self.maxsize,
            "buffer_depth": self.buffer_depth,
            "total_emitted": self._total_emitted,
            "total_consumed": self._total_consumed,
            "is_closed": self._closed,
        }

    async def emit(self, item: T) -> None:
        """Push an item into the stream, applying backpressure if buffer is full."""
        if self._closed:
            raise RuntimeError(f"Cannot emit to closed StageStream '{self.name}'")
        await self._queue.put(item)
        self._total_emitted += 1

    async def emit_batch(self, items: list[T] | tuple[T, ...]) -> None:
        """Push multiple items sequentially respecting queue bounds."""
        for item in items:
            await self.emit(item)

    async def close(self) -> None:
        """Close stream, signaling completion to downstream consumers."""
        if not self._closed:
            self._closed = True
            await self._queue.put(self._sentinel)

    async def __aiter__(self) -> AsyncIterator[T]:
        """Asynchronously iterate over stream items until closed."""
        while True:
            item = await self._queue.get()
            try:
                if item is self._sentinel:
                    # Put back sentinel for other concurrent consumers if any
                    await self._queue.put(self._sentinel)
                    break
                self._total_consumed += 1
                yield item  # type: ignore[misc]
            finally:
                self._queue.task_done()

    async def read_batch(self, max_batch_size: int = 100, timeout: float | None = 0.5) -> list[T]:
        """Read a batch of available items up to max_batch_size."""
        batch: list[T] = []
        try:
            while len(batch) < max_batch_size:
                try:
                    if timeout is not None and not batch:
                        item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                    else:
                        item = self._queue.get_nowait()
                except (asyncio.QueueEmpty, asyncio.TimeoutError):
                    break

                try:
                    if item is self._sentinel:
                        await self._queue.put(self._sentinel)
                        break
                    self._total_consumed += 1
                    batch.append(item)  # type: ignore[arg-type]
                finally:
                    self._queue.task_done()
        except Exception:
            pass
        return batch
