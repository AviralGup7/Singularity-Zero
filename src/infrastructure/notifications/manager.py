import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from src.infrastructure.notifications.base import (
    BaseNotifier,
    NotificationEvent,
    NotificationPriority,
    NotificationResult,
)

logger = logging.getLogger(__name__)

_CHANNEL_REGISTRY: dict[str, type[BaseNotifier]] = {}


def register_channel(name: str, notifier_cls: type[BaseNotifier]) -> None:
    _CHANNEL_REGISTRY[name] = notifier_cls


def get_channel(name: str) -> type[BaseNotifier] | None:
    return _CHANNEL_REGISTRY.get(name)


class ChannelEntry(BaseModel):
    name: str
    config: dict[str, Any]
    enabled: bool = Field(default=True)
    events: list[NotificationEvent] | None = Field(default=None)
    min_priority: NotificationPriority = Field(default=NotificationPriority.LOW)


class ManagerConfig(BaseModel):
    channels: list[ChannelEntry] = Field(default_factory=list)
    default_min_priority: NotificationPriority = Field(default=NotificationPriority.LOW)
    fail_fast: bool = Field(default=False)
    aggregate_results: bool = Field(default=True)
    deduplication_window_seconds: float = Field(default=60.0)
    max_concurrent_sends: int = Field(default=10, gt=0)


class NotificationManager:
    def __init__(self, config: ManagerConfig) -> None:
        self._config = config
        self._notifiers: list[BaseNotifier] = []
        self._channel_map: dict[str, BaseNotifier] = {}
        self._channel_filters: dict[str, ChannelEntry] = {}
        self._sent_hashes: dict[str, float] = {}
        self._semaphore = asyncio.Semaphore(config.max_concurrent_sends)
        self._logger = logging.getLogger(__name__)

    async def initialize(self) -> None:
        for entry in self._config.channels:
            if not entry.enabled:
                continue

            notifier = self._build_notifier(entry)
            if notifier is None:
                continue

            self._notifiers.append(notifier)
            self._channel_map[entry.name] = notifier
            self._channel_filters[entry.name] = entry

        self._logger.info(
            "NotificationManager initialized with %d channels: %s",
            len(self._notifiers),
            [n.channel_name for n in self._notifiers],
        )

    def _build_notifier(self, entry: ChannelEntry) -> BaseNotifier | None:
        notifier_cls = get_channel(entry.name)
        if notifier_cls is None:
            self._logger.warning("Unknown notification channel: %s", entry.name)
            return None

        try:
            config_cls = self._get_config_class(notifier_cls)
            config = config_cls(**entry.config)
            return notifier_cls(config)
        except Exception as exc:
            self._logger.error("Failed to initialize notifier %s: %s", entry.name, exc)
            return None

    def _get_config_class(self, notifier_cls: type[BaseNotifier]) -> type:
        import inspect

        sig = inspect.signature(notifier_cls.__init__)
        for param in sig.parameters.values():
            if param.name == "config" and param.annotation != inspect.Parameter.empty:
                return param.annotation

        from src.infrastructure.notifications.base import NotificationConfig

        return NotificationConfig

    def register_notifier(self, name: str, notifier: BaseNotifier) -> None:
        self._notifiers.append(notifier)
        self._channel_map[name] = notifier
        self._channel_filters[name] = ChannelEntry(name=name, config={})

    async def send(
        self,
        event: NotificationEvent,
        priority: NotificationPriority,
        title: str,
        message: str,
        metadata: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> list[NotificationResult]:
        if self._is_duplicate(event, priority, title, correlation_id):
            self._logger.debug("Duplicate notification suppressed: %s", title)
            return []

        tasks = []
        targets = []

        for notifier in self._notifiers:
            channel_name = notifier.channel_name
            entry = self._channel_filters.get(channel_name)

            if entry and entry.events and event not in entry.events:
                continue

            if entry and self._priority_below_threshold(priority, entry.min_priority):
                continue

            if self._priority_below_threshold(priority, notifier.config.min_priority):
                continue

            tasks.append(
                self._send_with_semaphore(
                    notifier, event, priority, title, message, metadata, correlation_id
                )
            )
            targets.append(channel_name)

        if not tasks:
            self._logger.debug(
                "No channels match event %s at priority %s", event.value, priority.value
            )
            return []

        self._logger.info(
            "Sending notification %s [%s] to %d channels: %s",
            title,
            priority.value,
            len(targets),
            targets,
        )

        if self._config.fail_fast:
            results = []
            for task in tasks:
                result = await task
                results.append(result)
                if not result.success:
                    break
            return results

        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed: list[NotificationResult] = []
        for item in results:
            if isinstance(item, Exception):
                processed.append(
                    NotificationResult(
                        success=False,
                        channel="unknown",
                        event=event.value,
                        priority=priority.value,
                        error=str(item),
                    )
                )
            else:
                processed.append(item)

        if self._config.aggregate_results:
            success_count = sum(1 for r in processed if r.success)
            self._logger.info(
                "Notification results: %d/%d channels succeeded",
                success_count,
                len(processed),
            )

        return processed

    async def _send_with_semaphore(
        self,
        notifier: BaseNotifier,
        event: NotificationEvent,
        priority: NotificationPriority,
        title: str,
        message: str,
        metadata: dict[str, Any] | None,
        correlation_id: str | None,
    ) -> NotificationResult:
        async with self._semaphore:
            return await notifier.send(
                event=event,
                priority=priority,
                title=title,
                message=message,
                metadata=metadata,
                correlation_id=correlation_id,
            )

    def _is_duplicate(
        self,
        event: NotificationEvent,
        priority: NotificationPriority,
        title: str,
        correlation_id: str | None,
    ) -> bool:
        if self._config.deduplication_window_seconds <= 0:
            return False

        key = f"{event.value}:{priority.value}:{title}:{correlation_id or ''}"
        now = datetime.now(UTC).timestamp()

        if key in self._sent_hashes:
            elapsed = now - self._sent_hashes[key]
            if elapsed < self._config.deduplication_window_seconds:
                return True

        self._sent_hashes[key] = now
        self._cleanup_old_hashes(now)
        return False

    def _cleanup_old_hashes(self, now: float) -> None:
        cutoff = now - self._config.deduplication_window_seconds * 2
        expired = [k for k, v in self._sent_hashes.items() if v < cutoff]
        for k in expired:
            del self._sent_hashes[k]

    @staticmethod
    def _priority_below_threshold(
        priority: NotificationPriority, threshold: NotificationPriority
    ) -> bool:
        order = {
            NotificationPriority.LOW: 0,
            NotificationPriority.MEDIUM: 1,
            NotificationPriority.HIGH: 2,
            NotificationPriority.CRITICAL: 3,
        }
        return order[priority] < order[threshold]

    async def send_finding(
        self,
        finding_title: str,
        finding_description: str,
        severity: str,
        target: str | None = None,
        endpoint: str | None = None,
        correlation_id: str | None = None,
    ) -> list[NotificationResult]:
        severity_to_priority = {
            "info": NotificationPriority.LOW,
            "low": NotificationPriority.LOW,
            "medium": NotificationPriority.MEDIUM,
            "high": NotificationPriority.HIGH,
            "critical": NotificationPriority.CRITICAL,
        }
        priority = severity_to_priority.get(severity.lower(), NotificationPriority.MEDIUM)

        event = (
            NotificationEvent.CRITICAL_VULNERABILITY
            if priority == NotificationPriority.CRITICAL
            else NotificationEvent.FINDING_DETECTED
        )

        metadata: dict[str, Any] = {
            "severity": severity,
        }
        if target:
            metadata["target"] = target
        if endpoint:
            metadata["endpoint"] = endpoint

        return await self.send(
            event=event,
            priority=priority,
            title=finding_title,
            message=finding_description,
            metadata=metadata,
            correlation_id=correlation_id,
        )

    async def send_scan_status(
        self,
        status: str,
        target: str,
        details: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> list[NotificationResult]:
        event_map = {
            "started": NotificationEvent.SCAN_STARTED,
            "completed": NotificationEvent.SCAN_COMPLETED,
            "failed": NotificationEvent.SCAN_FAILED,
            "timeout": NotificationEvent.PIPELINE_TIMEOUT,
        }
        event = event_map.get(status.lower(), NotificationEvent.CUSTOM)
        priority = (
            NotificationPriority.CRITICAL
            if status.lower() in ("failed", "timeout")
            else NotificationPriority.LOW
        )

        metadata: dict[str, Any] = {"target": target, "status": status}
        if details:
            metadata.update(details)

        title = f"Scan {status.capitalize()}: {target}"
        message = f"Security scan {status} for target: {target}"

        return await self.send(
            event=event,
            priority=priority,
            title=title,
            message=message,
            metadata=metadata,
            correlation_id=correlation_id,
        )

    async def send_error(
        self,
        error_title: str,
        error_message: str,
        correlation_id: str | None = None,
    ) -> list[NotificationResult]:
        return await self.send(
            event=NotificationEvent.SYSTEM_ERROR,
            priority=NotificationPriority.HIGH,
            title=error_title,
            message=error_message,
            correlation_id=correlation_id,
        )

    def get_channel(self, name: str) -> BaseNotifier | None:
        return self._channel_map.get(name)

    @property
    def channels(self) -> list[str]:
        return list(self._channel_map.keys())

    async def close(self) -> None:
        for notifier in self._notifiers:
            try:
                await notifier.close()
            except Exception as exc:
                self._logger.error("Error closing notifier %s: %s", notifier.channel_name, exc)
        self._notifiers.clear()
        self._channel_map.clear()
        self._channel_filters.clear()
        self._sent_hashes.clear()

    async def __aenter__(self) -> NotificationManager:
        await self.initialize()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        await self.close()


def _auto_register_channels() -> None:
    try:
        from src.infrastructure.notifications.email import EmailNotifier

        register_channel("email", EmailNotifier)
    except ImportError:
        pass
    try:
        from src.infrastructure.notifications.slack import SlackNotifier

        register_channel("slack", SlackNotifier)
    except ImportError:
        pass
    try:
        from src.infrastructure.notifications.webhook import WebhookNotifier

        register_channel("webhook", WebhookNotifier)
    except ImportError:
        pass


_auto_register_channels()
