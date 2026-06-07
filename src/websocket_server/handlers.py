"""WebSocket endpoint handlers.

Defines the WebSocket endpoint functions for real-time communication:
- /ws/scan-progress - Real-time scan progress updates
- /ws/job-status - Job status change notifications
- /ws/logs/{job_id} - Streaming logs for a specific job
- /ws/dashboard - General dashboard updates

Each handler authenticates the connection, manages subscriptions, and
dispatches outbound messages from the connection's message queue.
"""

import asyncio
import uuid
from typing import Any, cast

from starlette.websockets import WebSocket, WebSocketDisconnect

from src.core.logging.trace_logging import get_pipeline_logger
from src.websocket_server.auth import AuthenticationError, authenticate_websocket, send_auth_error
from src.websocket_server.broadcaster import Broadcaster
from src.websocket_server.heartbeat import HeartbeatMonitor
from src.websocket_server.manager import ConnectionInfo, ConnectionManager
from src.websocket_server.metrics import WS_AUTHZ_REJECTIONS
from src.websocket_server.protocol import (
    BaseMessage,
    ErrorMessage,
    MessageType,
    SubscribeMessage,
    UnsubscribeMessage,
)
from src.websocket_server.reconnect import ReconnectionManager

logger = get_pipeline_logger(__name__)


class WebSocketHook:
    """Base class / interface for custom WebSocket event hooks (middleware)."""

    async def on_connect(self, info: ConnectionInfo) -> bool:
        return True

    async def on_message(self, info: ConnectionInfo, msg: BaseMessage) -> BaseMessage | None:
        return msg

    async def on_subscribe(
        self, info: ConnectionInfo, message: SubscribeMessage
    ) -> bool:
        """Decide whether a connection may subscribe to a channel.

        Returning ``False`` rejects the subscription and the connection
        is closed with code ``4003``. The default implementation
        permits every subscription; deployments that need row-level
        authorization should subclass this hook.
        """
        return True

    async def on_broadcast(self, channel: str, msg: BaseMessage) -> None:
        pass


def _extract_job_id_from_channel(channel: str) -> str | None:
    """Return the job id from a ``job:<id>`` / ``logs:<id>`` channel.

    Returns ``None`` for any other channel format (including the
    ``target:`` prefix and the tenant-scoped ``global:<tenant>`` /
    ``dashboard:<tenant>`` channels).
    """
    if not channel:
        return None
    for prefix in ("job:", "logs:"):
        if channel.startswith(prefix):
            value = channel[len(prefix) :]
            return value or None
    return None


class WebSocketHandler:
    """Central handler for all WebSocket endpoint connections.

    Manages the connection lifecycle: authentication, subscription management,
    heartbeat monitoring, message dispatch, and graceful disconnect.

    Attributes:
        manager: Connection manager for tracking active connections.
        broadcaster: Message broadcaster for fan-out delivery.
        heartbeat: Heartbeat monitor for client liveness.
        reconnect: Reconnection manager for session resume.
        jwt_secret: Secret key for JWT validation.
        api_keys: Dict of valid API keys to user IDs.
        required_roles: Roles required for WebSocket access.
        job_ownership_checker: Optional callable
            ``(user_id, job_id) -> bool`` that decides whether the
            authenticated user is allowed to subscribe to ``job:<id>``
            or ``logs:<job_id>`` channels. ``None`` disables the
            per-job check (still subject to hook-level authorization).
        default_tenant_id: Tenant id used for tenant-scoped default
            channels (``global:<tenant>`` / ``dashboard:<tenant>``).
    """

    def __init__(
        self,
        manager: ConnectionManager,
        broadcaster: Broadcaster,
        heartbeat: HeartbeatMonitor,
        reconnect: ReconnectionManager,
        jwt_secret: str | None = None,
        api_keys: dict[str, str] | None = None,
        required_roles: set[str] | None = None,
        allowed_origins: set[str] | None = None,
        job_ownership_checker: Any | None = None,
        default_tenant_id: str = "default",
        require_tls: bool | None = None,
    ) -> None:
        """Initialize the WebSocket handler.

        Args:
            manager: Connection manager instance.
            broadcaster: Message broadcaster instance.
            heartbeat: Heartbeat monitor instance.
            reconnect: Reconnection manager instance.
            jwt_secret: JWT secret for authentication.
            api_keys: Valid API keys dict.
            required_roles: Required roles for access.
            allowed_origins: Set of allowed origin URIs to mitigate CSWSH.
            job_ownership_checker: Optional ``(user_id, job_id) -> bool``
                callable used to authorize per-job channel subscriptions.
            default_tenant_id: Tenant id used to namespace default
                global/dashboard channels.
            require_tls: Forwarded to :func:`authenticate_websocket`.
        """
        self.manager = manager
        self.broadcaster = broadcaster
        self.heartbeat = heartbeat
        self.reconnect = reconnect
        self.jwt_secret = jwt_secret
        self.api_keys = api_keys
        self.required_roles = required_roles
        self.allowed_origins = allowed_origins
        self.job_ownership_checker = job_ownership_checker
        self.default_tenant_id = default_tenant_id
        self.require_tls = require_tls
        self.hooks: list[WebSocketHook] = []
        self.compression_options: dict[str, Any] | None = None

        import os

        self.max_message_size = int(os.environ.get("WS_MAX_MESSAGE_SIZE", "131072"))
        self.rate_limit_capacity = float(os.environ.get("WS_RATE_LIMIT_CAPACITY", "100.0"))
        self.rate_limit_refill_rate = float(os.environ.get("WS_RATE_LIMIT_REFILL_RATE", "50.0"))

        if not jwt_secret and not api_keys:
            logger.warning(
                "WebSocket security alert: Neither jwt_secret nor api_keys are configured. "
                "Anonymous WebSocket access will be permitted if ALLOW_ANONYMOUS_WS is enabled."
            )

    def register_hook(self, hook: WebSocketHook) -> None:
        """Register a custom WebSocket hook/middleware."""
        self.hooks.append(hook)

    def _tenant_global_channel(self) -> str:
        """Return the tenant-scoped global channel for this handler."""
        return f"global:{self.default_tenant_id}"

    def _tenant_dashboard_channel(self) -> str:
        """Return the tenant-scoped dashboard channel for this handler."""
        return f"dashboard:{self.default_tenant_id}"

    async def handle_scan_progress(self, websocket: WebSocket) -> None:
        """Handle WebSocket connection for real-time scan progress.

        Clients receive progress updates for all jobs they subscribe to.
        Automatically subscribes to the tenant-scoped ``global:<tenant>``
        channel on connect.

        Args:
            websocket: The incoming WebSocket connection.
        """
        await self._handle_connection(
            websocket,
            default_channels={self._tenant_global_channel()},
            endpoint="scan-progress",
        )

    async def handle_job_status(self, websocket: WebSocket) -> None:
        """Handle WebSocket connection for job status notifications.

        Clients receive status change events for jobs they subscribe to.
        Supports subscribing to specific job IDs via the query parameter
        ``?job_id=<id>``.

        Args:
            websocket: The incoming WebSocket connection.
        """
        job_id = websocket.query_params.get("job_id")
        default_channels: set[str] = {self._tenant_global_channel()}
        if job_id:
            default_channels.add(f"job:{job_id}")

        await self._handle_connection(
            websocket,
            default_channels=default_channels,
            endpoint="job-status",
        )

    async def handle_job_logs(self, websocket: WebSocket, job_id: str) -> None:
        """Handle WebSocket connection for streaming job logs.

        Automatically subscribes to the log channel for the specified job.
        Clients receive log lines as they are produced by the pipeline.

        Args:
            websocket: The incoming WebSocket connection.
            job_id: The job whose logs to stream.
        """
        await self._handle_connection(
            websocket,
            default_channels={f"logs:{job_id}"},
            endpoint=f"logs/{job_id}",
        )

    async def handle_dashboard(self, websocket: WebSocket) -> None:
        """Handle WebSocket connection for general dashboard updates.

        Clients receive aggregated dashboard metrics, job summaries, and
        system health updates. Subscribes to the tenant-scoped
        ``global:<tenant>`` and ``dashboard:<tenant>`` channels.

        Args:
            websocket: The incoming WebSocket connection.
        """
        await self._handle_connection(
            websocket,
            default_channels={self._tenant_global_channel(), self._tenant_dashboard_channel()},
            endpoint="dashboard",
        )

    async def handle_evasion_telemetry(self, websocket: WebSocket) -> None:
        """Handle connections for DRL Policy Telemetry."""
        await self._handle_connection(
            websocket,
            default_channels={self._tenant_global_channel(), "telemetry"},
            endpoint="evasion-telemetry",
        )

    async def _handle_connection(
        self,
        websocket: WebSocket,
        default_channels: set[str],
        endpoint: str,
    ) -> None:
        """Core connection lifecycle handler.

        Performs authentication, registers the connection, starts heartbeat
        monitoring, processes inbound messages, and dispatches outbound
        messages until the client disconnects.

        Args:
            websocket: The incoming WebSocket connection.
            default_channels: Channels to auto-subscribe on connect.
            endpoint: Endpoint identifier for logging.
        """
        client = websocket.client
        client_ip = client.host if client else "unknown"
        connection_id = uuid.uuid4().hex  # Fix SEC-12: Full UUID

        try:
            auth = await authenticate_websocket(
                websocket,
                jwt_secret=self.jwt_secret,
                api_keys=self.api_keys,
                required_roles=self.required_roles,
                allowed_origins=self.allowed_origins,
                require_tls=self.require_tls,
            )
        except AuthenticationError as exc:
            logger.warning("Auth failed for %s on /ws/%s: %s", client_ip, endpoint, exc.detail)
            await send_auth_error(websocket, exc)
            return

        try:
            await websocket.accept()
        except Exception as e:
            # Fix Audit #400: Log error on accept
            logger.debug("WebSocket accept failed: %s", e, exc_info=True)
            return

        info = await self.manager.connect(
            websocket,
            user_id=auth.user_id,
            connection_id=connection_id,
            client_ip=client_ip,
        )

        if info is None:
            error_msg = ErrorMessage(
                code="connection_limit_reached",
                message="Too many active connections. Please close other tabs and reconnect.",
                recoverable=True,
            )
            try:
                await websocket.send_text(error_msg.to_json())
                await websocket.close(code=4009, reason="Connection limit reached")
            except Exception as e:
                # Fix #337: Elevate to WARNING
                logger.warning("Failed to send limit reached message to %s: %s", client_ip, e)
            return

        # Structured logging correlation: bind connection_id context variable if structlog is used
        try:
            import structlog

            structlog.context_var.bind_contextvars(connection_id=connection_id)
        except ImportError:
            pass

        # Execute on_connect hooks
        for hook in self.hooks:
            try:
                allowed = await hook.on_connect(info)
                if not allowed:
                    logger.warning("Connection %s rejected by on_connect hook", connection_id)
                    await websocket.close(code=4003, reason="Forbidden by event hook")
                    return
            except Exception as hook_exc:
                logger.error(
                    "Error in on_connect hook for connection %s: %s", connection_id, hook_exc
                )

        await self.broadcaster.start_message_dispatch(connection_id)
        await self.heartbeat.start(connection_id)

        # Per-connection reconnection token. The fingerprint combines the
        # authenticated user id, the client IP, and the endpoint so that
        # the same user connecting from two devices gets two independent
        # replay buffers instead of one evicting the other.
        fingerprint = self.reconnect.derive_fingerprint(
            auth.user_id, client_ip, endpoint, connection_id
        )
        reconnect_token, issued_fingerprint = self.reconnect.generate_token(
            auth.user_id, fingerprint=fingerprint
        )
        # Stash the fingerprint on the connection for later bookkeeping
        # (e.g. cleanup or "ack" path).
        try:
            info.user_id = auth.user_id  # already set by manager.connect
        except Exception:  # noqa: BLE001
            pass

        for channel in default_channels:
            await self.manager.add_to_group(connection_id, channel)
            self.reconnect.record_subscriptions(reconnect_token, {channel})

        await info.send_ack("connect", accepted=True)

        try:
            await self._message_loop(info, auth.user_id)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("Error in WebSocket %s handler for %s: %s", endpoint, connection_id, exc)
        finally:
            self.reconnect.record_subscriptions(
                reconnect_token,
                set(info.groups),
            )
            await self.heartbeat.stop(connection_id)
            await self.broadcaster.stop_message_dispatch(connection_id)
            await self.manager.disconnect(connection_id)
            # Suppress "unused" lint warning for the issued fingerprint.
            _ = issued_fingerprint

    async def _message_loop(
        self,
        info: ConnectionInfo,
        user_id: str,
    ) -> None:
        """Process inbound messages from a WebSocket connection.

        Handles subscribe, unsubscribe, heartbeat pong, and ack messages.
        Unknown message types receive an error response.

        Args:
            info: ConnectionInfo for the client.
            user_id: Authenticated user ID.
        """
        import time

        while True:
            try:
                raw = await info.websocket.receive_text()
            except WebSocketDisconnect:
                break
            except Exception as e:
                # Fix Audit #86: Log inbound error
                logger.debug("Inbound WebSocket error for %s: %s", info.connection_id, e)
                break

            # SEC-8 / SEC-10: Cap inbound message size
            if len(raw) > self.max_message_size:
                await info.websocket.close(code=1009, reason="Message too large")
                break

            now = time.monotonic()
            elapsed = now - info.last_rate_limit_time
            info.last_rate_limit_time = now
            info.rate_limit_tokens = min(
                self.rate_limit_capacity,
                info.rate_limit_tokens + elapsed * self.rate_limit_refill_rate,
            )  # refill rate

            if info.rate_limit_tokens < 1.0:
                error = ErrorMessage(
                    code="rate_limit_exceeded",
                    message="Message rate limit exceeded",
                    recoverable=True,
                )
                try:
                    await info.websocket.send_text(error.to_json())
                except Exception as e:
                    logger.debug("Failed to send rate limit error to %s: %s", info.connection_id, e)
                    break
                await asyncio.sleep(0.05)  # Backpressure
                continue

            info.rate_limit_tokens -= 1.0

            info.touch()

            try:
                message = BaseMessage.from_json(raw)
            except ValueError as exc:
                error = ErrorMessage(
                    code="invalid_message",
                    message=f"Failed to parse message: {exc}",
                    recoverable=True,
                )
                try:
                    await info.websocket.send_text(error.to_json())
                except Exception as e:
                    # Fix Audit #86: Log error sending invalid message notice
                    logger.debug(
                        "Failed to send invalid message notice to %s: %s", info.connection_id, e
                    )
                    break
                continue

            # Execute on_message hooks
            hook_swallowed = False
            for hook in self.hooks:
                try:
                    processed_message = await hook.on_message(info, message)
                    if processed_message is None:
                        hook_swallowed = True
                        break
                    message = processed_message
                except Exception as hook_exc:
                    logger.error("Error in on_message hook: %s", hook_exc)

            if hook_swallowed:
                continue

            if message.type == MessageType.SUBSCRIBE:
                await self._handle_subscribe(info, cast(SubscribeMessage, message))
            elif message.type == MessageType.UNSUBSCRIBE:
                await self._handle_unsubscribe(info, cast(UnsubscribeMessage, message))
            elif message.type == MessageType.HEARTBEAT:
                logger.debug("Received heartbeat from %s", info.connection_id)
            elif message.type == MessageType.ACK:
                logger.debug("Received ack from %s", info.connection_id)
            else:
                error = ErrorMessage(
                    code="unsupported_message_type",
                    message=f"Server does not handle inbound {message.type.value} messages",
                    recoverable=True,
                )
                try:
                    await info.websocket.send_text(error.to_json())
                except Exception as e:
                    # Fix Audit #86: Log error
                    logger.debug(
                        "Failed to send unsupported type error to %s: %s", info.connection_id, e
                    )
                    break

    async def _handle_subscribe(
        self,
        info: ConnectionInfo,
        message: SubscribeMessage,
    ) -> None:
        """Process a subscription request.

        Validates that the authenticated user is permitted to access the
        requested channel (per-job ownership check + custom
        ``on_subscribe`` hooks), then adds the connection to the
        requested group, sends an ack, and replays any buffered
        messages newer than ``resume_from``.

        Args:
            info: ConnectionInfo for the client.
            message: SubscribeMessage to process.
        """
        channel = message.channel

        # ----------------------------------------------------------
        # Authorization: on_subscribe hooks + per-job ownership check
        # ----------------------------------------------------------
        if not await self._authorize_subscription(info, message):
            try:
                WS_AUTHZ_REJECTIONS.labels(
                    reason="forbidden", channel=channel or "-"
                ).inc()
            except Exception:  # noqa: BLE001
                pass
            try:
                err = ErrorMessage(
                    code="forbidden",
                    message=f"Not authorized to subscribe to {channel}",
                    details={"channel": channel},
                    recoverable=False,
                )
                await info.websocket.send_text(err.to_json())
            except Exception:  # noqa: BLE001
                pass
            try:
                await info.websocket.close(code=4003, reason="Forbidden")
            except Exception:  # noqa: BLE001
                pass
            logger.warning(
                "Subscription to %s denied for user %s on connection %s",
                channel,
                info.user_id,
                info.connection_id,
            )
            return

        await self.manager.add_to_group(info.connection_id, channel)

        if message.job_id:
            job_channel = f"job:{message.job_id}"
            await self.manager.add_to_group(info.connection_id, job_channel)

        if message.target:
            target_channel = f"target:{message.target}"
            await self.manager.add_to_group(info.connection_id, target_channel)

        await info.send_ack(message.id, accepted=True)

        if message.resume_from is not None:
            # Sequence-aware replay: we look up the token by both the
            # current connection's fingerprint and the user id. When the
            # manager cannot disambiguate (e.g. tests), we fall back to
            # the user-only lookup.
            token = self.reconnect.get_token_for_user(info.user_id)
            replay: list[str] = []
            if token:
                replay = self.reconnect.get_replay_messages(
                    token, resume_from=message.resume_from
                )
            for msg_json in replay:
                try:
                    await info.message_queue.put(msg_json)
                except asyncio.QueueFull:
                    logger.warning(
                        "Reconnection replay failed: queue full for connection %s",
                        info.connection_id,
                    )
                    try:
                        await info.websocket.close(
                            code=1008, reason="Reconnection replay buffer overflow"
                        )
                    except Exception:  # noqa: S110
                        pass
                    break

        logger.info(
            "Connection %s subscribed to channel %s",
            info.connection_id,
            channel,
        )

    async def _authorize_subscription(
        self,
        info: ConnectionInfo,
        message: SubscribeMessage,
    ) -> bool:
        """Run all subscription authorization checks.

        Returns ``True`` only if every registered hook permits the
        subscription *and* the per-job ownership check (when one is
        configured) allows access to the requested job channel.
        """
        # Custom on_subscribe hooks. Returning ``False`` from any hook
        # short-circuits the chain and rejects the subscription.
        for hook in self.hooks:
            try:
                allowed = await hook.on_subscribe(info, message)
            except Exception as hook_exc:  # noqa: BLE001
                logger.error(
                    "Error in on_subscribe hook for connection %s: %s",
                    info.connection_id,
                    hook_exc,
                )
                allowed = False
            if not allowed:
                return False

        # Per-job ownership check. Applies to ``job:<id>`` and
        # ``logs:<job_id>`` channels (and any explicit ``job_id`` on the
        # message).
        job_ids_to_check: set[str] = set()
        channel = message.channel or ""
        derived = _extract_job_id_from_channel(channel)
        if derived:
            job_ids_to_check.add(derived)
        if message.job_id:
            job_ids_to_check.add(message.job_id)

        if not job_ids_to_check:
            return True

        if self.job_ownership_checker is None:
            # No row-level policy configured. In production deployments
            # the recommendation is to always configure this; for dev we
            # allow the subscription through to preserve behaviour.
            return True

        for jid in job_ids_to_check:
            try:
                permitted = bool(
                    self.job_ownership_checker(info.user_id, jid)
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "job_ownership_checker raised for user=%s job=%s: %s",
                    info.user_id,
                    jid,
                    exc,
                )
                permitted = False
            if not permitted:
                return False
        return True

    async def _handle_unsubscribe(
        self,
        info: ConnectionInfo,
        message: UnsubscribeMessage,
    ) -> None:
        """Process an unsubscription request.

        Removes the connection from the requested group and sends an ack.

        Args:
            info: ConnectionInfo for the client.
            message: UnsubscribeMessage to process.
        """
        await self.manager.remove_from_group(info.connection_id, message.channel)

        await info.send_ack(message.id, accepted=True)

        logger.info(
            "Connection %s unsubscribed from channel %s",
            info.connection_id,
            message.channel,
        )
