"""Data models for the alerting system.

Provides Alert, AlertRule, AlertChannel dataclasses and all alert-related enums.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AlertSeverity(StrEnum):
    """Alert severity levels."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class AlertState(StrEnum):
    """Alert state in its lifecycle."""

    FIRING = "firing"
    RESOLVED = "resolved"
    PENDING = "pending"
    SUPPRESSED = "suppressed"


class ChannelType(StrEnum):
    """Alert notification channel types."""

    WEBHOOK = "webhook"
    EMAIL = "email"
    SLACK = "slack"


@dataclass
class Alert:
    """Represents a single alert instance.

    Attributes:
        name: Unique alert rule name.
        severity: Alert severity level.
        state: Current alert state.
        message: Human-readable alert message.
        value: The metric value that triggered the alert.
        threshold: The threshold that was exceeded.
        labels: Alert labels for routing and grouping.
        annotations: Additional alert context.
        first_fired: Unix timestamp when the alert first fired.
        last_fired: Unix timestamp of the most recent firing.
        fingerprint: Unique hash for deduplication.
    """

    name: str
    severity: AlertSeverity
    state: AlertState = AlertState.PENDING
    message: str = ""
    value: float = 0.0
    threshold: float = 0.0
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    first_fired: float = 0.0
    last_fired: float = 0.0
    fingerprint: str = ""

    def __post_init__(self) -> None:
        """Generate fingerprint if not provided."""
        if not self.fingerprint:
            fp_data = json.dumps({"name": self.name, "labels": self.labels}, sort_keys=True)
            self.fingerprint = hashlib.sha256(fp_data.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "severity": self.severity.value,
            "state": self.state.value,
            "message": self.message,
            "value": self.value,
            "threshold": self.threshold,
            "labels": self.labels,
            "annotations": self.annotations,
            "first_fired": self.first_fired,
            "last_fired": self.last_fired,
            "fingerprint": self.fingerprint,
        }


@dataclass
class AlertRule:
    """Defines conditions that trigger an alert.

    Attributes:
        name: Unique rule name.
        severity: Alert severity when triggered.
        metric_name: Name of the metric to evaluate.
        condition: Comparison operator (gt, lt, gte, lte, eq).
        threshold: Value to compare against.
        for_duration: Seconds the condition must be true before firing.
        labels: Labels to attach to triggered alerts.
        annotations: Template annotations for alert messages.
        enabled: Whether the rule is active.
    """

    name: str
    severity: AlertSeverity
    metric_name: str
    condition: str
    threshold: float
    for_duration: float = 0.0
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    enabled: bool = True

    def evaluate(self, value: float) -> bool:
        """Check if the current value triggers this rule.

        Args:
            value: Current metric value.

        Returns:
            True if the condition is met.
        """
        match self.condition:
            case "gt":
                return value > self.threshold
            case "lt":
                return value < self.threshold
            case "gte":
                return value >= self.threshold
            case "lte":
                return value <= self.threshold
            case "eq":
                return value == self.threshold
            case _:
                return False


@dataclass
class AlertChannel:
    """Notification channel for alert delivery.

    Attributes:
        name: Channel identifier.
        channel_type: Type of channel (webhook, email, slack).
        config: Channel-specific configuration.
        enabled: Whether the channel is active.
    """

    name: str
    channel_type: ChannelType
    config: dict[str, str] = field(default_factory=dict)
    enabled: bool = True

    async def send(self, alert: Alert) -> bool:
        """Send an alert through this channel.

        Retained as a compatibility wrapper for call sites that still invoke
        ``AlertChannel.send(...)`` directly.
        """
        from src.infrastructure.observability.alerts.channels import send_alert

        return await send_alert(self, alert)
