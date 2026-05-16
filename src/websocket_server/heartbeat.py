"""WebSocket heartbeat monitoring.

Implements a ping/pong keep-alive mechanism with configurable intervals,
timeout detection, and automatic disconnection of unresponsive clients.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

from starlette.websockets import WebSocketState

from src.core.logging.trace_logging import get_pipeline_logger
from src.websocket_server.manager import ConnectionManager
from src.websocket_server.protocol import HeartbeatMessage  # Fix #358: top-level import

if TYPE_CHECKING:
    from src.websocket_server.manager import ConnectionInfo

# Fix #356: use project logger instead of stdlib logging
logger = get_pipeline_logger(__name__)


class HeartbeatMonitor:
    """Monitors WebSocket client liveness via periodic ping messages.

    Sends heartbeat messages at a configurable interval and tracks the
    time since the last client activity. If a client fails to respond
    within the timeout window, it is automatically disconnected.

    Fix #357: _running is now per-connection (tracked via _stop_events)
    so stopping one connection does not interfere with others.

    Attributes:
        manager: Connection manager for tracking and cleanup.
        interval_seconds: Seconds between heartbeat pings (default 30).
        timeout_seconds: Seconds of inactivity before disconnecting (default 90).
        _tasks: Dict mapping connection_id to the heartbeat asyncio.Task.
        _stop_events: Dict mapping connection_id to its cancellation Event.
    """

    def __init__(
        self,
        manager: ConnectionManager,
        interval_seconds: float = 30.0,
        timeout_seconds: float = 90.0,
        broadcaster: Any | None = None,
    ) -> None:
        """Initialize the heartbeat monitor.

        Args:
            manager: Connection manager instance.
            interval_seconds: Interval between heartbeat pings.
            timeout_seconds: Inactivity timeout before disconnection.
        """
        self.manager = manager
        self.interval_seconds = interval_seconds
        self.timeout_seconds = timeout_seconds
        self.broadcaster = broadcaster
        self._tasks: dict[str, asyncio.Task[None]] = {}
        # Fix #357: per-connection stop events instead of a single shared _running flag
        self._stop_events: dict[str, asyncio.Event] = {}

    async def start(self, connection_id: str) -> None:
        """Start heartbeat monitoring for a connection.

        Args:
            connection_id: Connection to monitor.
        """
        if connection_id in self._tasks:
            return

        # Fix #357: per-connection stop event for immediate cancellation
        stop_event = asyncio.Event()
        self._stop_events[connection_id] = stop_event

        task = asyncio.create_task(
            self._monitor_loop(connection_id, stop_event),
            name=f"heartbeat-{connection_id}",
        )
        self._tasks[connection_id] = task
        logger.debug("Heartbeat started for connection %s", connection_id)

    async def stop(self, connection_id: str) -> None:
        """Stop heartbeat monitoring for a connection.

        Args:
            connection_id: Connection to stop monitoring.
        """
        # Signal the per-connection loop to exit immediately
        stop_event = self._stop_events.pop(connection_id, None)
        if stop_event is not None:
            stop_event.set()

        task = self._tasks.pop(connection_id, None)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        logger.debug("Heartbeat stopped for connection %s", connection_id)

    async def stop_all(self) -> None:
        """Stop all active heartbeat monitors."""
        conn_ids = list(self._tasks.keys())
        for conn_id in conn_ids:
            await self.stop(conn_id)

    async def _monitor_loop(self, connection_id: str, stop_event: asyncio.Event) -> None:
        """Main monitoring loop for a single connection.

        Fix #361: Uses asyncio.Event for immediate wakeup on stop signal,
        instead of polling with while self._running.

        Sends periodic heartbeat messages and checks for timeout.
        Disconnects the client if it exceeds the inactivity timeout.
        """
        while not stop_event.is_set():
            try:
                # Fix #361: wait with timeout; stop_event.set() wakes immediately
                try:
                    await asyncio.wait_for(
                        stop_event.wait(), timeout=self.interval_seconds
                    )
                    # stop_event was set — exit cleanly
                    break
                except TimeoutError:
                    pass  # Normal: interval elapsed, proceed with heartbeat

                info = await self.manager.get_connection(connection_id)
                if info is None or info.closed:
                    break

                if info.is_stale(self.timeout_seconds):
                    logger.warning(
                        "Connection %s timed out (inactive for %.0fs), disconnecting",
                        connection_id,
                        time.time() - info.last_activity,
                    )
                    await self._disconnect_client(info)
                    break

                if info.websocket.client_state != WebSocketState.CONNECTED:
                    break

                heartbeat = HeartbeatMessage(
                    server_time=time.time(),
                    interval=self.interval_seconds,
                )
                await info.websocket.send_text(heartbeat.to_json())
                logger.debug("Heartbeat sent to connection %s", connection_id)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(
                    "Heartbeat error for connection %s: %s",
                    connection_id,
                    exc,
                )
                break

    async def _disconnect_client(self, info: ConnectionInfo) -> None:
        """Disconnect a client that has timed out.

        Args:
            info: ConnectionInfo for the timed-out client.
        """
        try:
            if info.websocket.client_state == WebSocketState.CONNECTED:
                # Fix #360: Use 1001 (Going Away) — correct code for server-initiated close
                await info.websocket.close(
                    code=1001,
                    reason="Heartbeat timeout",
                )
        except Exception as e:
            logger.debug(
                "Failed to close websocket during heartbeat timeout for %s: %s",
                info.connection_id,
                e,
            )
        if self.broadcaster is not None:
            await self.broadcaster.stop_message_dispatch(info.connection_id)
        await self.manager.disconnect(info.connection_id)
