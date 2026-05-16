"""Core alert manager — evaluates rules against metrics and dispatches alerts.

Provides AlertManager with rule management, evaluation, deduplication,
suppression windows, and notification delivery through channels.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, cast

from src.infrastructure.observability.alerts.channels import send_alert
from src.infrastructure.observability.alerts.models import (
    Alert,
    AlertChannel,
    AlertRule,
    AlertSeverity,
    AlertState,
)
from src.infrastructure.observability.config import get_config
from src.infrastructure.observability.metrics import get_metrics


class AlertManager:
    """Manages alert rules, evaluation, and notification delivery.

    Supports threshold-based and anomaly-based alerting with
    deduplication, suppression windows, and multiple channels.
    """

    def __init__(
        self,
        deduplication_window: float = 300.0,
        suppression_window: float = 900.0,
        min_severity: str = "warning",
    ) -> None:
        """Initialize the alert manager.

        Args:
            deduplication_window: Seconds to deduplicate identical alerts.
            suppression_window: Seconds to suppress repeated alerts.
            min_severity: Minimum severity to process and notify.
        """
        self._rules: dict[str, AlertRule] = {}
        self._channels: list[AlertChannel] = []
        self._active_alerts: dict[str, Alert] = {}
        self._alert_history: list[Alert] = []
        self._firing_since: dict[str, float] = {}
        self._last_notification: dict[str, float] = {}
        self._dedup_window = deduplication_window
        self._suppression_window = suppression_window
        self._min_severity = AlertSeverity(min_severity)
        self._notification_count = 0
        self._evaluation_count = 0

    def add_rule(self, rule: AlertRule) -> None:
        """Add an alert rule.

        Args:
            rule: The AlertRule to add.
        """
        self._rules[rule.name] = rule

    def remove_rule(self, name: str) -> None:
        """Remove an alert rule.

        Args:
            name: Rule name to remove.
        """
        self._rules.pop(name, None)

    def add_channel(self, channel: AlertChannel) -> None:
        """Add a notification channel.

        Args:
            channel: The AlertChannel to add.
        """
        self._channels.append(channel)

    def clear_channels(self) -> None:
        """Remove all notification channels."""
        self._channels.clear()

    async def evaluate(self) -> list[Alert]:
        """Evaluate all alert rules against current metrics.

        Returns:
            List of newly fired alerts.
        """
        self._evaluation_count += 1
        metrics = get_metrics()
        all_metrics = metrics.get_all()
        newly_fired: list[Alert] = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            metric_value = self._get_metric_value(all_metrics, rule.metric_name)
            if metric_value is None:
                continue

            triggered = rule.evaluate(metric_value)

            if triggered:
                alert_key = rule.name
                if alert_key not in self._firing_since:
                    self._firing_since[alert_key] = time.time()

                duration_firing = time.time() - self._firing_since[alert_key]
                if duration_firing >= rule.for_duration:
                    alert = self._create_alert(rule, metric_value)

                    if self._is_deduplicated(alert):
                        alert.state = AlertState.SUPPRESSED
                        continue

                    if self._is_suppressed(alert):
                        alert.state = AlertState.SUPPRESSED
                        continue

                    if alert_key not in self._active_alerts:
                        alert.state = AlertState.FIRING
                        alert.first_fired = time.time()
                        self._active_alerts[alert_key] = alert
                        newly_fired.append(alert)
                    else:
                        existing = self._active_alerts[alert_key]
                        existing.last_fired = time.time()
                        existing.value = metric_value
                        existing.state = AlertState.FIRING
                        if existing not in newly_fired:
                            newly_fired.append(existing)
            else:
                if rule.name in self._firing_since:
                    del self._firing_since[rule.name]
                if rule.name in self._active_alerts:
                    self._active_alerts[rule.name].state = AlertState.RESOLVED
                    self._active_alerts[rule.name].last_fired = time.time()

        for alert in newly_fired:
            if alert.state == AlertState.FIRING:
                await self._notify(alert)

        return newly_fired

    def _get_metric_value(
        self,
        all_metrics: dict[str, Any],
        metric_name: str,
    ) -> float | None:
        """Get a metric value from the metrics registry.

        Args:
            all_metrics: Dict from MetricsRegistry.get_all().
            metric_name: Full metric name to look up.

        Returns:
            Metric value, or None if not found.
        """
        for category in ("counters", "gauges", "histograms", "summaries"):
            if metric_name in all_metrics.get(category, {}):
                data = all_metrics[category][metric_name]
                if isinstance(data, (int, float)):
                    return float(data)
                if isinstance(data, dict):
                    return float(cast(Any, data.get("sum", data.get("mean", data.get("count", 0)))))
        return None

    def _create_alert(self, rule: AlertRule, value: float) -> Alert:
        """Create an Alert from a triggered rule.

        Args:
            rule: The triggered AlertRule.
            value: The metric value that triggered it.

        Returns:
            A new Alert instance.
        """
        message = rule.annotations.get("message", "")
        if not message:
            message = f"{rule.name}: {rule.metric_name} = {value} (threshold: {rule.threshold})"

        return Alert(
            name=rule.name,
            severity=rule.severity,
            state=AlertState.PENDING,
            message=message,
            value=value,
            threshold=rule.threshold,
            labels=rule.labels,
            annotations=rule.annotations,
            last_fired=time.time(),
        )

    def _is_deduplicated(self, alert: Alert) -> bool:
        """Check if an alert is a duplicate within the dedup window.

        Args:
            alert: The alert to check.

        Returns:
            True if the alert is a duplicate.
        """
        if alert.fingerprint in self._last_notification:
            elapsed = time.time() - self._last_notification[alert.fingerprint]
            return elapsed < self._dedup_window
        return False

    def _is_suppressed(self, alert: Alert) -> bool:
        """Check if an alert should be suppressed.

        Args:
            alert: The alert to check.

        Returns:
            True if the alert is in the suppression window.
        """
        if alert.fingerprint in self._last_notification:
            elapsed = time.time() - self._last_notification[alert.fingerprint]
            return elapsed < self._suppression_window
        return False

    async def _notify(self, alert: Alert) -> None:
        """Send an alert through all configured channels.

        Args:
            alert: The alert to notify.
        """
        self._notification_count += 1
        self._last_notification[alert.fingerprint] = time.time()

        tasks = [send_alert(channel, alert) for channel in self._channels if channel.enabled]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def get_active_alerts(self) -> list[Alert]:
        """Get all currently active (firing) alerts.

        Returns:
            List of firing alerts.
        """
        return [a for a in self._active_alerts.values() if a.state == AlertState.FIRING]

    def get_alert_history(self, limit: int = 50) -> list[Alert]:
        """Get recent alert history.

        Args:
            limit: Maximum number of alerts to return.

        Returns:
            List of recent alerts, most recent first.
        """
        return list(reversed(self._alert_history))[:limit]

    def get_stats(self) -> dict[str, Any]:
        """Get alert manager statistics.

        Returns:
            Dict with evaluation count, notification count, and active alerts.
        """
        return {
            "evaluation_count": self._evaluation_count,
            "notification_count": self._notification_count,
            "active_alerts": len(self.get_active_alerts()),
            "total_rules": len(self._rules),
            "channels": len(self._channels),
            "rules": {name: rule.enabled for name, rule in self._rules.items()},
        }

    def clear(self) -> None:
        """Clear all active alerts and history."""
        self._active_alerts.clear()
        self._alert_history.clear()
        self._firing_since.clear()
        self._last_notification.clear()


_alert_manager_instance: AlertManager | None = None


def get_alert_manager() -> AlertManager:
    """Get the global alert manager instance."""
    global _alert_manager_instance
    if _alert_manager_instance is None:
        config = get_config()
        alert_config = config.alerts
        _alert_manager_instance = AlertManager(
            deduplication_window=alert_config.deduplication_window_seconds,
            suppression_window=alert_config.suppression_window_seconds,
            min_severity=alert_config.min_alert_severity,
        )
    return _alert_manager_instance
