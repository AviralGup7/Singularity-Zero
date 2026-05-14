import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class NotificationPriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationEvent(StrEnum):
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    FINDING_DETECTED = "finding_detected"
    CRITICAL_VULNERABILITY = "critical_vulnerability"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SYSTEM_ERROR = "system_error"
    PIPELINE_TIMEOUT = "pipeline_timeout"
    CUSTOM = "custom"


class NotificationConfig(BaseModel):
    enabled: bool = Field(default=True)
    min_priority: NotificationPriority = Field(default=NotificationPriority.LOW)
    include_metadata: bool = Field(default=True)
    retry_count: int = Field(default=3, ge=0, le=10)
    retry_delay_seconds: float = Field(default=5.0, gt=0)
    timeout_seconds: float = Field(default=30.0, gt=0)


class NotificationResult(BaseModel):
    success: bool
    channel: str
    event: str
    priority: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    error: str | None = Field(default=None)
    response_data: dict[str, Any] = Field(default_factory=dict)


class NotificationPayload(BaseModel):
    event: NotificationEvent
    priority: NotificationPriority
    title: str
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = Field(default="cyber-security-pipeline")
    correlation_id: str | None = Field(default=None)


class BaseNotifier(ABC):
    def __init__(self, config: NotificationConfig, channel_name: str) -> None:
        self._config = config
        self._channel_name = channel_name
        self._logger = logging.getLogger(f"{__name__}.{channel_name}")

    @property
    def channel_name(self) -> str:
        return self._channel_name

    @property
    def config(self) -> NotificationConfig:
        return self._config

    async def send(
        self,
        event: NotificationEvent,
        priority: NotificationPriority,
        title: str,
        message: str,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> NotificationResult:
        if not self._config.enabled:
            self._logger.debug("Notifier %s is disabled, skipping", self._channel_name)
            return NotificationResult(
                success=False,
                channel=self._channel_name,
                event=event.value,
                priority=priority.value,
                error="Notifier disabled",
            )

        if self._should_filter(priority):
            self._logger.debug(
                "Priority %s below threshold for %s",
                priority.value,
                self._channel_name,
            )
            return NotificationResult(
                success=False,
                channel=self._channel_name,
                event=event.value,
                priority=priority.value,
                error="Filtered by priority threshold",
            )

        payload = NotificationPayload(
            event=event,
            priority=priority,
            title=title,
            message=message,
            metadata=metadata or {},
            correlation_id=correlation_id,
        )

        last_error: Exception | None = None
        for attempt in range(self._config.retry_count + 1):
            try:
                result = await self._do_send(payload)
                self._logger.info(
                    "Notification sent via %s: %s [%s]",
                    self._channel_name,
                    event.value,
                    priority.value,
                )
                return result
            except Exception as exc:
                last_error = exc
                self._logger.warning(
                    "Attempt %d/%d failed for %s: %s",
                    attempt + 1,
                    self._config.retry_count + 1,
                    self._channel_name,
                    exc,
                )
                if attempt < self._config.retry_count:
                    import asyncio

                    await asyncio.sleep(self._config.retry_delay_seconds)

        self._logger.error(
            "All %d attempts failed for %s: %s",
            self._config.retry_count + 1,
            self._channel_name,
            last_error,
        )
        return NotificationResult(
            success=False,
            channel=self._channel_name,
            event=event.value,
            priority=priority.value,
            error=str(last_error),
        )

    def _should_filter(self, priority: NotificationPriority) -> bool:
        priority_order = {
            NotificationPriority.LOW: 0,
            NotificationPriority.MEDIUM: 1,
            NotificationPriority.HIGH: 2,
            NotificationPriority.CRITICAL: 3,
        }
        return priority_order[priority] < priority_order[self._config.min_priority]

    @abstractmethod
    async def _do_send(self, payload: NotificationPayload) -> NotificationResult: ...

    async def close(self) -> None:
        pass

    async def __aenter__(self) -> BaseNotifier:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        await self.close()
