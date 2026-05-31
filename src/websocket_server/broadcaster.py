"""Message broadcasting with publish/subscribe pattern.

Provides fan-out broadcasting to multiple connections, message deduplication,
backpressure handling, and per-connection async message queues.
"""

import asyncio
import json
import os
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any

from starlette.websockets import WebSocketState  # Fix #369: top-level import

from src.core.logging.trace_logging import get_pipeline_logger
from src.websocket_server.manager import ConnectionManager
from src.websocket_server.protocol import BaseMessage
from src.websocket_server.metrics import WS_MESSAGES, WS_LATENCY, WS_REDIS_FANOUT

# Fix #362: use project-wide structured logger
logger = get_pipeline_logger(__name__)

REDIS_TIMEOUT_SECONDS = 5.0
REDIS_PUBLISH_RETRIES = 2
REDIS_RECONNECT_SECONDS = 30.0


class CircuitBreaker:
    """Circuit breaker pattern for Redis Pub/Sub integration."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.last_state_change = 0.0

    def record_success(self) -> None:
        self.failures = 0
        self.state = "CLOSED"

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.state = "OPEN"
            self.last_state_change = time.time()
            logger.error("Redis Pub/Sub circuit breaker is now OPEN due to %d consecutive failures", self.failures)

    def allow_request(self) -> bool:
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if time.time() - self.last_state_change > self.recovery_timeout:
                self.state = "HALF_OPEN"
                self.last_state_change = time.time()
                logger.info("Redis Pub/Sub circuit breaker entered HALF_OPEN state; attempting retry")
                return True
            return False
        return True  # HALF_OPEN


class Broadcaster:
    """Broadcasts messages to WebSocket connections using pub/sub pattern.

    Supports broadcasting to individual connections, groups (by job_id or target),
    or all connected clients. Includes message deduplication and backpressure
    handling that drops the oldest messages when a client's queue is full.

    Attributes:
        manager: Connection manager for resolving target connections.
        dedup_window: Number of recent message IDs to track for deduplication.
        backpressure_drop_oldest: Whether to drop oldest messages on queue overflow.
        _seen_ids: Set of recently seen message IDs for deduplication.
        _broadcast_count: Total number of messages broadcast.
        _drop_count: Total number of messages dropped due to backpressure.
    """

    def __init__(
        self,
        manager: ConnectionManager,
        dedup_window: int = 1000,
        backpressure_drop_oldest: bool = True,
        backpressure_drain_fraction: float = 0.5,
        redis_url: str | None = None,
        redis_channel: str = "ws:broadcasts",
        enable_redis: bool | None = None,
    ) -> None:
        """Initialize the broadcaster.

        Args:
            manager: Connection manager instance.
            dedup_window: Size of the deduplication window.
            backpressure_drop_oldest: Drop oldest messages when queue is full.
            backpressure_drain_fraction: Fraction of the queue to drain on overflow.
        """
        self.manager = manager
        self.dedup_window = int(os.environ.get("WS_DEDUP_WINDOW", str(dedup_window)))
        self.backpressure_drop_oldest = backpressure_drop_oldest
        if not 0 < backpressure_drain_fraction <= 1:
            raise ValueError("backpressure_drain_fraction must be between 0 and 1")
        self.backpressure_drain_fraction = float(os.environ.get("WS_BACKPRESSURE_DRAIN_FRACTION", str(backpressure_drain_fraction)))
        # Fix #363: Use OrderedDict for FIFO dedup window eviction.
        # set.pop() removes an arbitrary element, not the oldest.
        self._seen_ids: OrderedDict[str, None] = OrderedDict()
        self._seen_ids_lock = threading.Lock()
        self._broadcast_count: int = 0
        self._drop_count: int = 0
        self._lock = asyncio.Lock()
        self._redis_url = redis_url
        self._redis_channel = redis_channel
        self._redis_enabled = True if enable_redis is None else enable_redis
        self._redis_client: Any = None
        self._redis_pubsub: Any = None
        self._subscriber_task: asyncio.Task[None] | None = None
        self._dispatch_tasks: dict[str, asyncio.Task[None]] = {}
        self._delivery_tasks: set[asyncio.Task[Any]] = set()
        self._worker_id = uuid.uuid4().hex
        self._redis_breaker = CircuitBreaker()
        self._redis_degraded_until = 0.0

    def _dedup_key(self, message_id: str, scope: str = "") -> str:
        return f"{scope}:{message_id}" if scope else message_id

    def _is_duplicate(self, message_id: str, scope: str = "") -> bool:
        """Check if a message has already been processed."""
        dedup_key = self._dedup_key(message_id, scope)
        with self._seen_ids_lock:
            if dedup_key in self._seen_ids:
                return True

            self._seen_ids[dedup_key] = None
            # Fix #363: FIFO eviction — remove oldest entries when window is exceeded.
            while len(self._seen_ids) > self.dedup_window:
                self._seen_ids.popitem(last=False)  # Remove oldest (FIFO)

        return False

    async def start(self) -> None:
        """Start Redis Pub/Sub fan-out when configured."""
        current_task = asyncio.current_task()
        reconnecting_from_subscriber = (
            self._subscriber_task is not None and current_task is self._subscriber_task
        )
        if not self._redis_enabled or (self._subscriber_task is not None and not reconnecting_from_subscriber):
            return

        if self._redis_url is None:
            self._redis_url = os.environ.get("WS_REDIS_URL") or os.environ.get("REDIS_URL")

        if not self._redis_url:
            return

        try:
            import redis.asyncio as redis

            self._redis_client = redis.from_url(
                self._redis_url,
                decode_responses=True,
                socket_connect_timeout=REDIS_TIMEOUT_SECONDS,
                socket_timeout=REDIS_TIMEOUT_SECONDS,
                retry_on_timeout=True,
                health_check_interval=30,
                max_connections=20,
            )
            await asyncio.wait_for(self._redis_client.ping(), timeout=REDIS_TIMEOUT_SECONDS)
            self._redis_pubsub = self._redis_client.pubsub()
            await asyncio.wait_for(
                self._redis_pubsub.subscribe(self._redis_channel),
                timeout=REDIS_TIMEOUT_SECONDS,
            )
            if not reconnecting_from_subscriber:
                self._subscriber_task = asyncio.create_task(
                    self._redis_subscribe_loop(),
                    name="ws-redis-broadcaster",
                )
            logger.info("Redis WebSocket broadcaster subscribed to %s", self._redis_channel)
        except Exception as exc:
            logger.warning("Redis WebSocket broadcaster degraded: %s", exc)
            self._redis_degraded_until = time.monotonic() + REDIS_RECONNECT_SECONDS
            await self.stop()

    async def stop(self) -> None:
        """Stop Redis Pub/Sub resources."""
        if self._delivery_tasks:
            for task in list(self._delivery_tasks):
                task.cancel()
            try:
                await asyncio.gather(*self._delivery_tasks, return_exceptions=True)
            except Exception:
                pass
            self._delivery_tasks.clear()

        if self._subscriber_task:
            self._subscriber_task.cancel()
            try:
                await self._subscriber_task
            except asyncio.CancelledError:
                pass
            self._subscriber_task = None

        if self._redis_pubsub is not None:
            try:
                await asyncio.wait_for(
                    self._redis_pubsub.unsubscribe(self._redis_channel),
                    timeout=REDIS_TIMEOUT_SECONDS,
                )
                close = getattr(self._redis_pubsub, "aclose", self._redis_pubsub.close)
                await close()
            except Exception as exc:
                logger.debug("Redis Pub/Sub close failed: %s", exc)
            self._redis_pubsub = None

        if self._redis_client is not None:
            try:
                close = getattr(self._redis_client, "aclose", self._redis_client.close)
                await close()
            except Exception as exc:
                logger.debug("Redis client close failed: %s", exc)
            self._redis_client = None

    async def stop_message_dispatch(self, connection_id: str) -> None:
        """Stop the dispatch task for a single connection."""
        task = self._dispatch_tasks.pop(connection_id, None)
        if task is None:
            return

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def _publish(
        self,
        *,
        scope: str,
        target: str,
        message: BaseMessage,
        exclude: set[str] | None = None,
    ) -> bool:
        """Publish a broadcast envelope to Redis."""
        if not self._redis_enabled or not self._redis_url:
            return False

        if not self._redis_breaker.allow_request():
            logger.debug("Redis circuit breaker is OPEN; skipping publish to Redis")
            return False
        if time.monotonic() < self._redis_degraded_until:
            return False

        await self.start()
        if self._redis_client is None:
            return False

        envelope = {
            "source": self._worker_id,
            "scope": scope,
            "target": target,
            "message": message.to_json(),
            "exclude": sorted(exclude or set()),
        }
        try:
            await self._publish_with_retries(json.dumps(envelope))
            WS_REDIS_FANOUT.labels(direction="publish").inc()
            self._redis_breaker.record_success()
            return True
        except Exception as exc:
            self._redis_breaker.record_failure()
            self._redis_degraded_until = time.monotonic() + REDIS_RECONNECT_SECONDS
            logger.warning("Redis WebSocket publish failed; falling back locally: %s", exc)
            return False

    async def _redis_subscribe_loop(self) -> None:
        """Receive Redis Pub/Sub envelopes with exponential backoff reconnection."""
        backoff = 1.0
        max_backoff = 60.0

        while self._redis_enabled:
            try:
                if self._redis_pubsub is None:
                    await self.start()
                    if self._redis_pubsub is None:
                        raise ConnectionError("Failed to initialize Redis Pub/Sub")

                logger.debug("Redis WebSocket subscribe loop active on %s", self._redis_channel)
                async for item in self._redis_pubsub.listen():
                    if item.get("type") != "message":
                        continue

                    raw = item.get("data")
                    if not isinstance(raw, (str, bytes)):
                        continue

                    try:
                        envelope = json.loads(raw)
                        WS_REDIS_FANOUT.labels(direction="subscribe").inc()
                        task = asyncio.create_task(
                            self._deliver_envelope(envelope),
                            name=f"ws-deliver-{uuid.uuid4().hex[:8]}",
                        )
                        self._delivery_tasks.add(task)
                        task.add_done_callback(self._delivery_tasks.discard)
                        task.add_done_callback(self._log_task_error)
                        backoff = 1.0  # Reset backoff on successful message
                        self._redis_breaker.record_success()
                    except (TypeError, ValueError, json.JSONDecodeError) as exc:
                        logger.warning("Malformed Redis WS envelope: %s", exc)

            except asyncio.CancelledError:
                logger.info("Redis WebSocket subscribe loop cancelled")
                break
            except Exception as exc:
                self._redis_breaker.record_failure()
                logger.error("Redis WS loop failure (retrying in %.1fs): %s", backoff, exc)
                await self._close_redis_handles()
                self._redis_pubsub = None
                self._redis_degraded_until = time.monotonic() + min(backoff, REDIS_RECONNECT_SECONDS)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2.0, max_backoff)

    async def _deliver_envelope(self, envelope: dict[str, Any]) -> int:
        """Deliver a Redis broadcast envelope to local connections."""
        # Safety check: don't deliver messages published by this same worker
        if envelope.get("source") == self._worker_id:
            return 0

        message_json = envelope.get("message")
        if not isinstance(message_json, str):
            return 0

        try:
            message = BaseMessage.from_json(message_json)
            scope = str(envelope.get("scope") or "")
            target = str(envelope.get("target") or "")
            exclude_raw = envelope.get("exclude") or []
            exclude = (
                {str(item) for item in exclude_raw} if isinstance(exclude_raw, list) else set()
            )

            return await self._deliver_local(scope, target, message, exclude, skip_redis=True)
        except Exception as exc:
            logger.error("Envelope delivery failed: %s", exc)
            return 0

    def _log_task_error(self, task: asyncio.Task) -> None:
        """Done-callback that logs exceptions from fire-and-forget delivery tasks."""
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("Redis WS envelope delivery task failed: %s", exc)

    async def _publish_with_retries(self, payload: str) -> None:
        delay = 0.1
        last_error: Exception | None = None
        for attempt in range(REDIS_PUBLISH_RETRIES + 1):
            try:
                await asyncio.wait_for(
                    self._redis_client.publish(self._redis_channel, payload),
                    timeout=REDIS_TIMEOUT_SECONDS,
                )
                return
            except Exception as exc:
                last_error = exc
                if attempt >= REDIS_PUBLISH_RETRIES:
                    break
                await asyncio.sleep(delay)
                delay *= 2
        raise last_error or RuntimeError("Redis publish failed")

    async def _close_redis_handles(self) -> None:
        if self._redis_pubsub is not None:
            try:
                close = getattr(self._redis_pubsub, "aclose", self._redis_pubsub.close)
                await close()
            except Exception as exc:
                logger.debug("Redis Pub/Sub close after failure failed: %s", exc)
            self._redis_pubsub = None
        if self._redis_client is not None:
            try:
                close = getattr(self._redis_client, "aclose", self._redis_client.close)
                await close()
            except Exception as exc:
                logger.debug("Redis client close after failure failed: %s", exc)
            self._redis_client = None

    async def _deliver_local(
        self,
        scope: str,
        target: str,
        message: BaseMessage,
        exclude: set[str] | None = None,
        skip_redis: bool = False,
    ) -> int:
        """Internal delivery logic for connections on this process instance."""
        if not skip_redis and self._redis_enabled:
            # Prefer Redis in distributed mode, but fall through to local delivery
            # when Redis is degraded so the sender does not silently drop messages.
            if await self._publish(scope=scope, target=target, message=message, exclude=exclude):
                return 1

        exclude = exclude or set()
        dedup_scope = f"{scope}:{target}"
        if self._is_duplicate(message.id, dedup_scope):
            return 0

        if scope == "connection":
            return int(await self._deliver_to_connection(target, message))
        if scope == "group":
            connections = await self.manager.get_group_connections(target)
        elif scope == "user":
            connections = await self.manager.get_user_connections(target)
        elif scope == "all":
            # Fix #365: use public get_all_connections() instead of accessing private _lock.
            connections = await self.manager.get_all_connections()
        else:
            return 0

        sent = 0
        for info in connections:
            if info.connection_id in exclude or info.closed:
                continue
            if await self._enqueue(info, message):
                sent += 1

        if sent > 0:
            WS_MESSAGES.labels(scope=scope).inc(sent)
            async with self._lock:
                self._broadcast_count += 1
        return sent

    async def _deliver_to_connection(self, connection_id: str, message: BaseMessage) -> bool:
        info = await self.manager.get_connection(connection_id)
        if info is None or info.closed:
            return False
        sent = await self._enqueue(info, message)
        if sent:
            async with self._lock:
                self._broadcast_count += 1
        return sent

    async def _enqueue(self, info: Any, message: BaseMessage) -> bool:
        """Add a message to a connection's outbound queue."""
        json_data = message.to_json()
        try:
            info.message_queue.put_nowait(json_data)
            return True
        except asyncio.QueueFull:
            # Fix #366: handle backpressure by dropping messages if configured
            await self._handle_backpressure(info, json_data)
            return True  # 'sent' in the sense it was handled by backpressure
        except Exception as exc:
            logger.error("Failed to enqueue message for %s: %s", info.connection_id, exc)
            return False

    async def broadcast_to_connection(
        self,
        connection_id: str,
        message: BaseMessage,
    ) -> bool:
        """Send a message to a specific connection.

        Args:
            connection_id: Target connection ID.
            message: Message to send.

        Returns:
            True if the message was sent, False if the connection was not found.
        """
        if await self._publish(scope="connection", target=connection_id, message=message):
            return True
        return bool(await self._deliver_local("connection", connection_id, message, skip_redis=True))

    async def broadcast_to_group(
        self,
        group: str,
        message: BaseMessage,
        exclude: set[str] | None = None,
    ) -> int:
        """Send a message to all connections in a group.

        Args:
            group: Group name (e.g., 'job:abc123', 'target:example.com').
            message: Message to send.
            exclude: Set of connection IDs to exclude.

        Returns:
            Number of connections the message was sent to.
        """
        if await self._publish(scope="group", target=group, message=message, exclude=exclude):
            return 1
        return await self._deliver_local("group", group, message, exclude, skip_redis=True)

    async def broadcast_to_user(
        self,
        user_id: str,
        message: BaseMessage,
        exclude: set[str] | None = None,
    ) -> int:
        """Send a message to all connections for a specific user.

        Args:
            user_id: Target user ID.
            message: Message to send.
            exclude: Set of connection IDs to exclude.

        Returns:
            Number of connections the message was sent to.
        """
        if await self._publish(scope="user", target=user_id, message=message, exclude=exclude):
            return 1
        return await self._deliver_local("user", user_id, message, exclude, skip_redis=True)

    async def broadcast_to_all(
        self,
        message: BaseMessage,
        exclude: set[str] | None = None,
    ) -> int:
        """Send a message to all connected clients.

        Args:
            message: Message to send.
            exclude: Set of connection IDs to exclude.

        Returns:
            Number of connections the message was sent to.
        """
        if await self._publish(scope="all", target="*", message=message, exclude=exclude):
            return 1
        return await self._deliver_local("all", "*", message, exclude, skip_redis=True)

    async def _handle_backpressure(
        self,
        info: Any,
        json_data: str,
    ) -> None:
        """Handle backpressure when a connection's message queue is full.

        If backpressure_drop_oldest is enabled, drains half the queue to
        make room for new messages. Otherwise, the message is silently dropped.

        Args:
            info: ConnectionInfo with the full queue.
            json_data: JSON message to enqueue.
        """
        self._drop_count += 1
        logger.warning(
            "Message queue full for connection %s (dropped=%d)",
            info.connection_id,
            self._drop_count,
        )

        if self.backpressure_drop_oldest:
            drain_count = max(1, int(info.message_queue.maxsize * self.backpressure_drain_fraction))
            for _ in range(drain_count):
                try:
                    info.message_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

            try:
                await info.message_queue.put(json_data)
                logger.info(
                    "Recovered from backpressure for connection %s",
                    info.connection_id,
                )
            except asyncio.QueueFull:
                logger.error(
                    "Failed to recover from backpressure for connection %s",
                    info.connection_id,
                )

    async def start_message_dispatch(
        self,
        connection_id: str,
    ) -> asyncio.Task[None]:
        """Start a task that dispatches queued messages to a connection.

        Reads from the connection's message queue and sends each message
        over the WebSocket. Runs until the connection is closed.

        Args:
            connection_id: Connection to dispatch messages for.

        Returns:
            The asyncio.Task running the dispatch loop.
        """
        existing = self._dispatch_tasks.get(connection_id)
        if existing is not None and not existing.done():
            return existing

        task = asyncio.create_task(
            self._dispatch_loop(connection_id),
            name=f"dispatch-{connection_id}",
        )
        self._dispatch_tasks[connection_id] = task

        def _drop_completed_task(
            completed: asyncio.Task[None], connection_id: str = connection_id
        ) -> None:
            if self._dispatch_tasks.get(connection_id) is completed:
                self._dispatch_tasks.pop(connection_id, None)

        task.add_done_callback(_drop_completed_task)
        return task

    async def _dispatch_loop(self, connection_id: str) -> None:
        """Internal dispatch loop for a single connection.

        Args:
            connection_id: Connection to dispatch for.
        """
        info = await self.manager.get_connection(connection_id)
        if info is None:
            return

        while not info.closed:
            if info.websocket.client_state != WebSocketState.CONNECTED:
                break

            try:
                json_data = await info.message_queue.get()
                start_time = time.monotonic()
                await info.websocket.send_text(json_data)
                WS_LATENCY.observe(time.monotonic() - start_time)
                info.touch()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(
                    "Dispatch error for connection %s: %s",
                    connection_id,
                    exc,
                )
                break

    def get_stats(self) -> dict[str, Any]:
        """Get broadcasting statistics.

        Returns:
            Dict with broadcast and drop counts.
        """
        with self._seen_ids_lock:
            dedup_size = len(self._seen_ids)
        return {
            "broadcast_count": self._broadcast_count,
            "drop_count": self._drop_count,
            "dedup_window_size": dedup_size,
            "redis_enabled": self._redis_enabled,
            "redis_channel": self._redis_channel,
        }
