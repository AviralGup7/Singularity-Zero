"""WebSocket message protocol definitions.

Defines Pydantic models for all WebSocket message types used in the
cyber security test pipeline real-time communication layer.

Message types:
    - progress: Scan progress updates
    - status: Job status change notifications
    - log: Streaming log lines for a specific job
    - error: Error notifications
    - heartbeat: Ping/pong keep-alive messages
    - ack: Acknowledgement of received messages
    - subscribe: Request to subscribe to a channel
    - unsubscribe: Request to unsubscribe from a channel
"""

from __future__ import annotations

import json  # Fix #372: Move to top-level
import time
import uuid
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MessageType(StrEnum):
    """Enumeration of all WebSocket message types.

    Each message type corresponds to a specific category of real-time
    communication between the server and connected clients.
    """

    PROGRESS = "progress"
    STATUS = "status"
    LOG = "log"
    ERROR = "error"
    HEARTBEAT = "heartbeat"
    ACK = "ack"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"


class BaseMessage(BaseModel):
    """Base model for all WebSocket messages.

    Every message includes a unique ID, type discriminator, monotonically
    increasing sequence number for ordering, and an ISO-8601 timestamp.

    Attributes:
        id: Unique message identifier (UUID4 by default).
        type: Message type discriminator.
        sequence: Monotonically increasing sequence number for ordering.
                  Clients can use this to detect missed messages.
        timestamp: Unix timestamp when the message was created.
    """

    # Fix #371: Full UUID for better collision resistance in high-throughput scenarios
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    type: MessageType
    sequence: int = Field(default=0, ge=0)
    timestamp: float = Field(default_factory=time.time)

    def to_json(self) -> str:
        """Serialize the message to a JSON string.

        Returns:
            JSON string representation of the message.
        """
        return self.model_dump_json()

    @classmethod
    def from_json(cls, data: str) -> BaseMessage:
        """Deserialize a message from a JSON string.

        Args:
            data: JSON string to parse.

        Returns:
            Deserialized message instance.

        Raises:
            ValueError: If the JSON is invalid or missing required fields.
        """
        # Fix #372: Moved json import to top level
        raw = json.loads(data)
        msg_type = raw.get("type")
        if msg_type is None:
            raise ValueError("Message missing 'type' field")

        # Fix #373: Use cached module-level type map
        model_cls = _MESSAGE_TYPE_MAP.get(msg_type)
        if model_cls is None:
            raise ValueError(f"Unknown message type: {msg_type}")

        return model_cls.model_validate(raw)


class ProgressMessage(BaseMessage):
    """Real-time scan progress update.

    Sent when a pipeline stage advances or makes measurable progress.

    Attributes:
        job_id: Identifier of the job being tracked.
        stage: Current pipeline stage name.
        stage_label: Human-readable stage label.
        percent: Overall progress percentage (0-100).
        processed: Number of items processed in the current stage.
        total: Total number of items in the current stage.
        message: Optional status message describing current activity.
        target: Target URL or hostname being scanned.
    """

    type: MessageType = MessageType.PROGRESS
    job_id: str = Field(..., min_length=1)
    stage: str = Field(default="")
    stage_label: str = Field(default="")
    # Fix #374: Use float for sub-percent precision
    percent: float = Field(default=0.0, ge=0.0, le=100.0)
    processed: int | None = Field(default=None, ge=0)
    total: int | None = Field(default=None, ge=0)
    message: str = Field(default="")
    target: str = Field(default="")


class StatusMessage(BaseMessage):
    """Job status change notification.

    Sent when a job transitions between lifecycle states.

    Attributes:
        job_id: Identifier of the job.
        status: New job status (running, completed, failed, stopped).
        previous_status: Status before the transition.
        stage: Current pipeline stage.
        stage_label: Human-readable stage label.
        progress_percent: Overall progress percentage.
        error: Error message if the job failed.
        target: Target URL or hostname.
        metadata: Additional context about the status change.
    """

    type: MessageType = MessageType.STATUS
    job_id: str = Field(..., min_length=1)
    status: str = Field(..., min_length=1)
    previous_status: str = Field(default="")
    stage: str = Field(default="")
    stage_label: str = Field(default="")
    progress_percent: int = Field(default=0, ge=0, le=100)
    error: str | None = Field(default=None)
    target: str = Field(default="")
    metadata: dict[str, Any] = Field(default_factory=dict)


class LogMessage(BaseMessage):
    """Streaming log line for a specific job.

    Sent when a new log line is produced by a running job.

    Attributes:
        job_id: Identifier of the job producing the log.
        line: The log line content.
        source: Log source ('stdout' or 'stderr').
        level: Optional log level ('info', 'warning', 'error').
    """

    type: MessageType = MessageType.LOG
    job_id: str = Field(..., min_length=1)
    line: str = Field(..., min_length=1)
    source: str = Field(default="stdout")
    level: str = Field(default="info")


class ErrorMessage(BaseMessage):
    """Error notification sent to clients.

    Used for both protocol-level errors (auth failure, invalid message)
    and application-level errors (job failure, internal error).

    Attributes:
        code: Machine-readable error code.
        message: Human-readable error description.
        details: Optional additional error context.
        recoverable: Whether the client can recover from this error.
    """

    type: MessageType = MessageType.ERROR
    code: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)
    details: dict[str, Any] = Field(default_factory=dict)
    recoverable: bool = Field(default=True)


class HeartbeatMessage(BaseMessage):
    """Ping/pong keep-alive message.

    Sent periodically by the server to verify client liveness.
    Clients should respond with a matching heartbeat message.

    Attributes:
        server_time: Server timestamp for clock skew detection.
        interval: Recommended heartbeat interval in seconds.
    """

    type: MessageType = MessageType.HEARTBEAT
    server_time: float = Field(default_factory=time.time)
    interval: float = Field(default=30.0)


class AckMessage(BaseMessage):
    """Acknowledgement of a received message.

    Sent by the server to confirm receipt of a client message,
    or by the client to confirm receipt of a server message.

    Attributes:
        ack_id: ID of the message being acknowledged.
        accepted: Whether the message was accepted for processing.
        reason: Optional reason if the message was rejected.
    """

    type: MessageType = MessageType.ACK
    ack_id: str = Field(..., min_length=1)
    accepted: bool = Field(default=True)
    reason: str = Field(default="")


class SubscribeMessage(BaseMessage):
    """Request to subscribe to a channel.

    Clients send this to start receiving messages for a specific
    job, target, or global channel.

    Attributes:
        channel: Channel to subscribe to ('job:<id>', 'target:<name>', 'global').
        job_id: Optional job ID filter (used when channel is 'job:<id>').
        target: Optional target name filter (used when channel is 'target:<name>').
        resume_from: Optional sequence number to resume from (for reconnection).
    """

    type: MessageType = MessageType.SUBSCRIBE
    channel: str = Field(..., min_length=1)
    job_id: str | None = Field(default=None)
    target: str | None = Field(default=None)
    resume_from: int | None = Field(default=None, ge=0)


class UnsubscribeMessage(BaseMessage):
    """Request to unsubscribe from a channel.

    Clients send this to stop receiving messages for a channel.

    Attributes:
        channel: Channel to unsubscribe from.
    """

    type: MessageType = MessageType.UNSUBSCRIBE
    channel: str = Field(..., min_length=1)


Message = (
    ProgressMessage
    | StatusMessage
    | LogMessage
    | ErrorMessage
    | HeartbeatMessage
    | AckMessage
    | SubscribeMessage
    | UnsubscribeMessage
)

_MESSAGE_TYPE_MAP: dict[str, type[BaseMessage]] = {
    "progress": ProgressMessage,
    "status": StatusMessage,
    "log": LogMessage,
    "error": ErrorMessage,
    "heartbeat": HeartbeatMessage,
    "ack": AckMessage,
    "subscribe": SubscribeMessage,
    "unsubscribe": UnsubscribeMessage,
}
