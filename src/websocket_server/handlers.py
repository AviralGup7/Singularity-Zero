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

from starlette.websockets import WebSocket, WebSocketDisconnect

from src.websocket_server.auth import AuthenticationError, authenticate_websocket, send_auth_error
from src.websocket_server.broadcaster import Broadcaster
from src.websocket_server.heartbeat import HeartbeatMonitor
from src.websocket_server.manager import ConnectionInfo, ConnectionManager
from src.websocket_server.protocol import (
    AckMessage,
    BaseMessage,
    ErrorMessage,
    MessageType,
    SubscribeMessage,
    UnsubscribeMessage,
)
from src.websocket_server.reconnect import ReconnectionManager
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


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
        """
        self.manager = manager
        self.broadcaster = broadcaster
        self.heartbeat = heartbeat
        self.reconnect = reconnect
        self.jwt_secret = jwt_secret
        self.api_keys = api_keys
        self.required_roles = required_roles

    async def handle_scan_progress(self, websocket: WebSocket) -> None:
        """Handle WebSocket connection for real-time scan progress.

        Clients receive progress updates for all jobs they subscribe to.
        Automatically subscribes to the 'global' channel on connect.

        Args:
            websocket: The incoming WebSocket connection.
        """
        await self._handle_connection(
            websocket,
            default_channels={"global"},
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
        default_channels: set[str] = {"global"}
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
        system health updates.

        Args:
            websocket: The incoming WebSocket connection.
        """
        await self._handle_connection(
            websocket,
            default_channels={"global", "dashboard"},
            endpoint="dashboard",
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
        connection_id = uuid.uuid4().hex[:12]

        try:
            auth = await authenticate_websocket(
                websocket,
                jwt_secret=self.jwt_secret,
                api_keys=self.api_keys,
                required_roles=self.required_roles,
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

        await self.broadcaster.start_message_dispatch(connection_id)
        await self.heartbeat.start(connection_id)

        reconnect_token = self.reconnect.generate_token(auth.user_id)

        for channel in default_channels:
            await self.manager.add_to_group(connection_id, channel)
            self.reconnect.record_subscriptions(reconnect_token, {channel})

        welcome = AckMessage(
            ack_id="connect",
            accepted=True,
        )
        welcome.sequence = info.next_sequence()
        try:
            await info.message_queue.put(welcome.to_json())
        except asyncio.QueueFull:
            # Fix Audit #86: Log queue full
            logger.warning("Failed to send welcome message: connection %s queue full", connection_id)

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
        while True:
            try:
                raw = await info.websocket.receive_text()
            except WebSocketDisconnect:
                break
            except Exception as e:
                # Fix Audit #86: Log inbound error
                logger.debug("Inbound WebSocket error for %s: %s", info.connection_id, e)
                break

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
                    logger.debug("Failed to send invalid message notice to %s: %s", info.connection_id, e)
                    break
                continue

            if message.type == MessageType.SUBSCRIBE:
                await self._handle_subscribe(info, message)
            elif message.type == MessageType.UNSUBSCRIBE:
                await self._handle_unsubscribe(info, message)
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
                    logger.debug("Failed to send unsupported type error to %s: %s", info.connection_id, e)
                    break

    async def _handle_subscribe(
        self,
        info: ConnectionInfo,
        message: SubscribeMessage,
    ) -> None:
        """Process a subscription request.

        Adds the connection to the requested group and sends an ack.

        Args:
            info: ConnectionInfo for the client.
            message: SubscribeMessage to process.
        """
        channel = message.channel
        await self.manager.add_to_group(info.connection_id, channel)

        if message.job_id:
            job_channel = f"job:{message.job_id}"
            await self.manager.add_to_group(info.connection_id, job_channel)

        if message.target:
            target_channel = f"target:{message.target}"
            await self.manager.add_to_group(info.connection_id, target_channel)

        ack = AckMessage(
            ack_id=message.id,
            accepted=True,
        )
        ack.sequence = info.next_sequence()
        try:
            await info.message_queue.put(ack.to_json())
        except asyncio.QueueFull:
            # Fix Audit #86: Log queue full
            logger.warning("Failed to send subscribe ack: connection %s queue full", info.connection_id)

        if message.resume_from is not None:
            token = self.reconnect.get_token_for_user(info.user_id)
            replay = self.reconnect.get_replay_messages(token) if token else []
            for msg_json in replay:
                try:
                    await info.message_queue.put(msg_json)
                except asyncio.QueueFull:
                    # Already warned about queue full
                    break

        logger.info(
            "Connection %s subscribed to channel %s",
            info.connection_id,
            channel,
        )

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

        ack = AckMessage(
            ack_id=message.id,
            accepted=True,
        )
        ack.sequence = info.next_sequence()
        try:
            await info.message_queue.put(ack.to_json())
        except asyncio.QueueFull:
            # Fix Audit #86: Log queue full
            logger.warning("Failed to send unsubscribe ack: connection %s queue full", info.connection_id)

        logger.info(
            "Connection %s unsubscribed from channel %s",
            info.connection_id,
            message.channel,
        )
