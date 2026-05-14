"""Alerting system for the cyber security test pipeline.

Provides threshold-based and anomaly-based alert rules, multiple
notification channels (webhook, email, Slack), alert deduplication,
suppression windows, and pre-configured alerts for common pipeline issues.

Usage:
    from src.infrastructure.observability.alerts import get_alert_manager

    manager = get_alert_manager()
    await manager.evaluate()
"""

# Models (enums + dataclasses)
# Channel send helper
from src.infrastructure.observability.alerts.channels import send_alert

# Core manager
from src.infrastructure.observability.alerts.manager import (
    AlertManager,
    get_alert_manager,
)
from src.infrastructure.observability.alerts.models import (
    Alert,
    AlertChannel,
    AlertRule,
    AlertSeverity,
    AlertState,
    ChannelType,
)

# Pipeline-specific rules
from src.infrastructure.observability.alerts.pipeline_rules import (
    AlertRuleChecker,
    PipelineAlertRule,
    get_alert_rule_checker,
    register_default_alerts,
    register_pipeline_alert_rules,
)

__all__ = [
    # Enums
    "AlertSeverity",
    "AlertState",
    "ChannelType",
    # Data classes
    "Alert",
    "AlertRule",
    "AlertChannel",
    # Pipeline
    "PipelineAlertRule",
    "AlertRuleChecker",
    "register_pipeline_alert_rules",
    "get_alert_rule_checker",
    "register_default_alerts",
    # Manager
    "AlertManager",
    "get_alert_manager",
    # Channels
    "send_alert",
]
