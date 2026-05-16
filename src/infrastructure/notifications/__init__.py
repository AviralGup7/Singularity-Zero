from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.infrastructure.notifications.base import (
        BaseNotifier,
        NotificationConfig,
        NotificationEvent,
        NotificationPriority,
        NotificationResult,
    )
    from src.infrastructure.notifications.email import EmailConfig, EmailNotifier
    from src.infrastructure.notifications.manager import NotificationManager
    from src.infrastructure.notifications.slack import SlackConfig, SlackNotifier
    from src.infrastructure.notifications.webhook import WebhookConfig, WebhookNotifier


def __getattr__(name: str) -> Any:
    if name == "BaseNotifier":
        from src.infrastructure.notifications.base import BaseNotifier

        return BaseNotifier
    if name == "NotificationConfig":
        from src.infrastructure.notifications.base import NotificationConfig

        return NotificationConfig
    if name == "NotificationEvent":
        from src.infrastructure.notifications.base import NotificationEvent

        return NotificationEvent
    if name == "NotificationPriority":
        from src.infrastructure.notifications.base import NotificationPriority

        return NotificationPriority
    if name == "NotificationResult":
        from src.infrastructure.notifications.base import NotificationResult

        return NotificationResult
    if name == "EmailConfig":
        from src.infrastructure.notifications.email import EmailConfig

        return EmailConfig
    if name == "EmailNotifier":
        from src.infrastructure.notifications.email import EmailNotifier

        return EmailNotifier
    if name == "SlackConfig":
        from src.infrastructure.notifications.slack import SlackConfig

        return SlackConfig
    if name == "SlackNotifier":
        from src.infrastructure.notifications.slack import SlackNotifier

        return SlackNotifier
    if name == "WebhookConfig":
        from src.infrastructure.notifications.webhook import WebhookConfig

        return WebhookConfig
    if name == "WebhookNotifier":
        from src.infrastructure.notifications.webhook import WebhookNotifier

        return WebhookNotifier
    if name == "NotificationManager":
        from src.infrastructure.notifications.manager import NotificationManager

        return NotificationManager
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BaseNotifier",
    "EmailConfig",
    "EmailNotifier",
    "NotificationConfig",
    "NotificationEvent",
    "NotificationManager",
    "NotificationPriority",
    "NotificationResult",
    "SlackConfig",
    "SlackNotifier",
    "WebhookConfig",
    "WebhookNotifier",
]
