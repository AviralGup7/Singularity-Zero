"""SSE broadcaster for real-time notification streaming to the frontend.

Manages a set of connected SSE clients and provides a broadcast method
that NotificationManager calls to push events to the browser.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from starlette.requests import Request
from starlette.responses import StreamingResponse

logger = logging.getLogger(__name__)


class NotificationBroadcaster:
    """Manages SSE connections and broadcasts notification events."""

    def __init__(self) -> None:
        self._queues: dict[str, asyncio.Queue[dict[str, Any] | None]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, request: Request) -> StreamingResponse:
        """Register a new SSE client and return a StreamingResponse."""
        client_id = f"sse-{id(request)}-{time.time():.0f}"
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=256)

        async with self._lock:
            self._queues[client_id] = queue

        async def event_generator() -> Any:
            try:
                # Send initial heartbeat so the client knows the connection is alive
                yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': time.time()})}\n\n"

                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        data = await asyncio.wait_for(queue.get(), timeout=30.0)
                    except TimeoutError:
                        # Send keepalive comment
                        yield ": keepalive\n\n"
                        continue

                    if data is None:
                        # Sentinel: close the stream
                        break

                    yield f"data: {json.dumps(data)}\n\n"
            finally:
                async with self._lock:
                    self._queues.pop(client_id, None)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    async def broadcast(self, notification: dict[str, Any]) -> None:
        """Send a notification event to all connected SSE clients."""
        async with self._lock:
            dead_clients: list[str] = []
            for client_id, queue in self._queues.items():
                try:
                    queue.put_nowait(notification)
                except asyncio.QueueFull:
                    logger.warning("SSE queue full for client %s, dropping notification", client_id)
                    dead_clients.append(client_id)
            for cid in dead_clients:
                self._queues.pop(cid, None)

    @property
    def connection_count(self) -> int:
        return len(self._queues)


# Global singleton
_broadcaster: NotificationBroadcaster | None = None


def get_notification_broadcaster() -> NotificationBroadcaster:
    """Get or create the global notification broadcaster."""
    global _broadcaster
    if _broadcaster is None:
        _broadcaster = NotificationBroadcaster()
    return _broadcaster
