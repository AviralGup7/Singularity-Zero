"""WebSocket connection manager.

Provides thread-safe management of all active WebSocket connections with
support for per-user tracking, connection groups, automatic cleanup of
stale connections, and configurable connection limits.
"""

import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Any, cast

from starlette.websockets import WebSocket, WebSocketState

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

# Fix #308: use project-wide structured logger


@dataclass
class ConnectionInfo:
    """Metadata about a single WebSocket connection.

    Attributes:
        websocket: The underlying WebSocket instance.
        user_id: Authenticated user identifier.
        connection_id: Unique connection identifier.
        client_ip: Client IP address for rate limiting.
        connected_at: Unix timestamp when the connection was established.
        last_activity: Unix timestamp of the last message activity.
        groups: Set of group identifiers this connection belongs to.
        sequence: Next outbound message sequence number.
        message_queue: Async queue for outbound messages (backpressure buffer).
        max_queue_size: Maximum number of pending messages before dropping oldest.
        closed: Whether the connection has been closed.
    """

    websocket: WebSocket
    user_id: str
    connection_id: str
    client_ip: str
    connected_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    groups: set[str] = field(default_factory=set)
    _message_queue: asyncio.Queue[str] | None = field(default=None, repr=False)  # Fix #309
    sequence_generator: Any = field(
        default_factory=lambda: __import__("itertools").count()
    )  # Fix #310
    _sequence_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    max_queue_size: int = field(default=256)
    closed: bool = field(default=False)

    @property
    def message_queue(self) -> asyncio.Queue[str]:
        if self._message_queue is None:
            self._message_queue = asyncio.Queue(maxsize=self.max_queue_size)
        return self._message_queue

    def next_sequence(self) -> int:
        """Get and increment the next outbound message sequence number.

        Returns:
            Monotonically increasing sequence number.
        """
        with self._sequence_lock:
            return cast(int, next(self.sequence_generator))

    def touch(self) -> None:
        """Update the last activity timestamp."""
        self.last_activity = time.time()

    def is_stale(self, timeout_seconds: float) -> bool:
        """Check if the connection has been inactive for too long.

        Args:
            timeout_seconds: Seconds of inactivity before considering stale.

        Returns:
            True if the connection is stale.
        """
        return time.time() - self.last_activity > timeout_seconds


class ConnectionManager:
    """Manages all active WebSocket connections.

    Provides thread-safe and async-safe connection registry with per-user
    tracking, group-based broadcasting, automatic stale connection cleanup,
    and configurable per-user/IP connection limits.

    Attributes:
        connections: Dict mapping connection_id to ConnectionInfo.
        user_connections: Dict mapping user_id to set of connection_ids.
        group_connections: Dict mapping group name to set of connection_ids.
        ip_connections: Dict mapping client_ip to set of connection_ids.
        max_connections_per_user: Maximum connections allowed per user.
        max_connections_per_ip: Maximum connections allowed per IP.
        stale_timeout: Seconds of inactivity before a connection is stale.
        _lock: Async lock for thread-safe mutations.
    """

    def __init__(
        self,
        max_connections_per_user: int = 10,
        max_connections_per_ip: int = 20,
        stale_timeout: float = 300.0,
    ) -> None:
        """Initialize the connection manager.

        Args:
            max_connections_per_user: Max concurrent connections per user.
            max_connections_per_ip: Max concurrent connections per IP.
            stale_timeout: Seconds of inactivity before marking stale.
        """
        self.connections: dict[str, ConnectionInfo] = {}
        self.user_connections: dict[str, set[str]] = {}
        # Fix #336: Use plain dicts to avoid defaultdict auto-creating empty sets
        # for every group lookup (memory leak when groups are queried but not used).
        self.group_connections: dict[str, set[str]] = {}
        self.ip_connections: dict[str, set[str]] = {}
        self.max_connections_per_user = max_connections_per_user
        self.max_connections_per_ip = max_connections_per_ip
        self.stale_timeout = stale_timeout
        self._lock = asyncio.Lock()

    async def connect(
        self,
        websocket: WebSocket,
        user_id: str,
        connection_id: str,
        client_ip: str,
    ) -> ConnectionInfo | None:
        """Register a new WebSocket connection.

        Enforces per-user and per-IP connection limits. Rejects the
        connection if limits are exceeded.

        Args:
            websocket: The WebSocket instance to register.
            user_id: Authenticated user identifier.
            connection_id: Unique connection identifier.
            client_ip: Client IP address.

        Returns:
            ConnectionInfo if accepted, None if rejected due to limits.
        """
        async with self._lock:
            user_connections = self.user_connections.setdefault(user_id, set())
            ip_connections = self.ip_connections.setdefault(client_ip, set())

            if len(user_connections) >= self.max_connections_per_user:
                logger.warning(
                    "Connection limit reached for user %s (%d/%d)",
                    user_id,
                    len(user_connections),
                    self.max_connections_per_user,
                )
                return None

            if len(ip_connections) >= self.max_connections_per_ip:
                logger.warning(
                    "Connection limit reached for IP %s (%d/%d)",
                    client_ip,
                    len(ip_connections),
                    self.max_connections_per_ip,
                )
                return None

            info = ConnectionInfo(
                websocket=websocket,
                user_id=user_id,
                connection_id=connection_id,
                client_ip=client_ip,
            )

            self.connections[connection_id] = info
            user_connections.add(connection_id)
            ip_connections.add(connection_id)

            logger.info(
                "Connection registered: id=%s user=%s ip=%s (total=%d)",
                connection_id,
                user_id,
                client_ip,
                len(self.connections),
            )
            return info

    async def disconnect(self, connection_id: str) -> None:
        """Remove a connection and clean up all its group memberships.

        Args:
            connection_id: The connection to remove.
        """
        async with self._lock:
            info = self.connections.pop(connection_id, cast(Any, None))
            if info is None:
                return

            info.closed = True

            self.user_connections[info.user_id].discard(connection_id)
            if not self.user_connections[info.user_id]:
                del self.user_connections[info.user_id]

            self.ip_connections[info.client_ip].discard(connection_id)
            if not self.ip_connections[info.client_ip]:
                del self.ip_connections[info.client_ip]

            for group in list(info.groups):
                self.group_connections[group].discard(connection_id)
                if not self.group_connections[group]:
                    del self.group_connections[group]

            logger.info(
                "Connection removed: id=%s user=%s (remaining=%d)",
                connection_id,
                info.user_id,
                len(self.connections),
            )

    async def add_to_group(self, connection_id: str, group: str) -> bool:
        """Add a connection to a group for targeted broadcasting.

        Args:
            connection_id: The connection to add.
            group: Group name (e.g., 'job:abc123', 'target:example.com').

        Returns:
            True if the connection was added, False if not found.
        """
        async with self._lock:
            info = self.connections.get(connection_id)
            if info is None:
                return False

            info.groups.add(group)
            self.group_connections.setdefault(group, set()).add(connection_id)
            return True

    async def remove_from_group(self, connection_id: str, group: str) -> bool:
        """Remove a connection from a group.

        Args:
            connection_id: The connection to remove.
            group: Group name to remove from.

        Returns:
            True if the connection was removed, False if not found.
        """
        async with self._lock:
            info = self.connections.get(connection_id)
            if info is None:
                return False

            info.groups.discard(group)
            self.group_connections[group].discard(connection_id)
            if not self.group_connections[group]:
                del self.group_connections[group]
            return True

    async def get_connection(self, connection_id: str) -> ConnectionInfo | None:
        """Retrieve connection info by ID.

        Args:
            connection_id: Connection identifier.

        Returns:
            ConnectionInfo if found, None otherwise.
        """
        return self.connections.get(connection_id)

    async def get_user_connections(self, user_id: str) -> list[ConnectionInfo]:
        """Get all active connections for a user.

        Args:
            user_id: User identifier.

        Returns:
            List of ConnectionInfo for the user.
        """
        # Fix #353: Snapshot under the lock to prevent race with concurrent disconnect().
        async with self._lock:
            conn_ids = set(self.user_connections.get(user_id, set()))
        return [self.connections[cid] for cid in conn_ids if cid in self.connections]

    async def get_group_connections(self, group: str) -> list[ConnectionInfo]:
        """Get all active connections in a group.

        Args:
            group: Group name.

        Returns:
            List of ConnectionInfo in the group.
        """
        conn_ids = self.group_connections.get(group, set())
        return [self.connections[cid] for cid in conn_ids if cid in self.connections]

    async def get_active_count(self) -> int:
        """Get the total number of active connections.

        Returns:
            Number of active connections.
        """
        return len(self.connections)

    async def get_all_connections(self) -> list[ConnectionInfo]:
        """Get all active connections.

        Returns:
            List of all ConnectionInfo.
        """
        async with self._lock:
            return list(self.connections.values())

    async def cleanup_stale(self) -> list[str]:
        """Find and remove stale connections.

        Scans all connections and removes those that have exceeded the
        stale timeout.

        Returns:
            List of removed connection IDs.
        """
        stale_ids: list[str] = []
        async with self._lock:
            for conn_id, info in list(self.connections.items()):
                if info.is_stale(self.stale_timeout):
                    stale_ids.append(conn_id)

            # Fix #311: Inline disconnect logic under the same lock
            for conn_id in stale_ids:
                info = self.connections.pop(conn_id, cast(Any, None))
                if info is None:
                    continue

                info.closed = True

                self.user_connections[info.user_id].discard(conn_id)
                if not self.user_connections[info.user_id]:
                    del self.user_connections[info.user_id]

                self.ip_connections[info.client_ip].discard(conn_id)
                if not self.ip_connections[info.client_ip]:
                    del self.ip_connections[info.client_ip]

                for group in list(info.groups):
                    self.group_connections[group].discard(conn_id)
                    if not self.group_connections[group]:
                        del self.group_connections[group]

        if stale_ids:
            logger.info("Cleaned up %d stale connections", len(stale_ids))

        return stale_ids

    async def close_all(self) -> None:
        """Close all active WebSocket connections.

        Sends a close frame to every connected client and removes all
        connection records.
        """
        # Fix #312: snapshot connection records under lock to avoid race when new
        # connections register concurrently during shutdown.
        async with self._lock:
            conns = list(self.connections.values())

        for info in conns:
            if info.websocket.client_state == WebSocketState.CONNECTED:
                try:
                    await info.websocket.close(code=1001, reason="Server shutting down")
                except Exception as e:
                    logger.debug("Failed to close connection %s cleanly: %s", info.connection_id, e)
            await self.disconnect(info.connection_id)

        logger.info("All %d connections closed", len(conns))

    async def update_activity(self, connection_id: str) -> None:
        """Update the last activity timestamp for a connection.

        Args:
            connection_id: Connection to update.
        """
        async with self._lock:
            info = self.connections.get(connection_id)
            if info:
                info.touch()
