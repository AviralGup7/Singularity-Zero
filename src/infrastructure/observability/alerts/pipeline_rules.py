"""Pipeline-specific alert rules.

Provides PipelineAlertRule, AlertRuleChecker, and registration of
standard pipeline alert rules evaluated after each pipeline stage.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.infrastructure.observability.alerts.manager import get_alert_manager
from src.infrastructure.observability.alerts.models import (
    Alert,
    AlertRule,
    AlertSeverity,
    AlertState,
)

logger = logging.getLogger(__name__)


@dataclass
class PipelineAlertRule:
    """Rule for pipeline-specific alerting evaluated against pipeline state.

    Attributes:
        name: Unique rule identifier.
        severity: The alert severity when triggered.
        condition: A callable taking (stage_name: str, state: dict) -> bool.
        message_template: Template for the alert message.
        notification_channels: List of channel names to notify.
        enabled: Whether the rule is active.
    """

    name: str
    severity: AlertSeverity
    condition: Callable[[str, dict[str, Any]], bool]
    message_template: str
    notification_channels: list[str] = field(default_factory=list)
    enabled: bool = True


class AlertRuleChecker:
    """Evaluates pipeline-specific alert rules after each pipeline stage.

    Rules are defined as PipelineAlertRule instances with a callable condition
    that receives the stage name and current pipeline state. When a condition
    evaluates to True, an alert is generated and optionally dispatched to
    notification channels.
    """

    def __init__(self, manager=None) -> None:
        """Initialize the rule checker.

        Args:
            manager: AlertManager for dispatching alerts. Uses global if None.
        """
        self._rules: dict[str, PipelineAlertRule] = {}
        self._manager = manager or get_alert_manager()
        self._fired_history: list[dict[str, Any]] = []

    def add_rule(self, rule: PipelineAlertRule) -> None:
        """Add a pipeline alert rule.

        Args:
            rule: The PipelineAlertRule to add.
        """
        self._rules[rule.name] = rule

    def remove_rule(self, name: str) -> None:
        """Remove a pipeline alert rule.

        Args:
            name: Rule name to remove.
        """
        self._rules.pop(name, None)

    def check_rules(self, stage_name: str, state: dict[str, Any]) -> list[Alert]:
        """Evaluate all pipeline alert rules for the current stage.

        Args:
            stage_name: Name of the completed stage.
            state: Current pipeline state (from PipelineContext.result).

        Returns:
            List of newly fired alerts.
        """
        fired: list[Alert] = []

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            try:
                triggered = rule.condition(stage_name, state)
            except Exception as exc:
                logger.warning("Alert rule %s evaluation error: %s", rule.name, exc)
                continue

            if triggered:
                alert = Alert(
                    name=rule.name,
                    severity=rule.severity,
                    state=AlertState.FIRING,
                    message=rule.message_template.format(
                        stage=stage_name,
                        state=state,
                    ),
                    labels={
                        "stage": stage_name,
                        "rule_type": "pipeline_state",
                    },
                    last_fired=time.time(),
                )
                fired.append(alert)
                self._fired_history.append(
                    {
                        "rule": rule.name,
                        "stage": stage_name,
                        "severity": rule.severity.value,
                        "message": alert.message,
                        "timestamp": time.time(),
                    }
                )
                logger.warning("Alert fired: %s at stage %s", rule.name, stage_name)

        return fired

    def get_fired_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent alert firing history.

        Args:
            limit: Maximum entries to return.

        Returns:
            List of recent alert events, newest first.
        """
        return list(reversed(self._fired_history))[:limit]


_min_subdomain_threshold = 5


def _check_pipeline_failure(_stage: str, state: dict[str, Any]) -> bool:
    module_metrics = state.get("module_metrics", {})
    if not isinstance(module_metrics, dict):
        return False
    return any(
        isinstance(m, dict) and str(m.get("status", "")) in ("error", "timeout", "failed")
        for m in module_metrics.values()
    )


def register_pipeline_alert_rules(checker: AlertRuleChecker | None = None) -> AlertRuleChecker:
    """Register the standard pipeline alert rules.

    Rules registered:
    - CRITICAL_FINDING_DISCOVERED: Any finding with severity=critical.
    - SCOPE_VIOLATION: Request made outside scope.
    - PIPELINE_FAILURE: Stage has failed status.
    - TOOL_UNAVAILABLE: A configured tool was not found on PATH.
    - RECON_COVERAGE_LOW: Subdomain count below minimum threshold.

    Args:
        checker: AlertRuleChecker to register with. Creates new if None.

    Returns:
        The AlertRuleChecker instance with rules registered.
    """
    if checker is None:
        checker = AlertRuleChecker()

    checker.add_rule(
        PipelineAlertRule(
            name="CRITICAL_FINDING_DISCOVERED",
            severity=AlertSeverity.CRITICAL,
            condition=lambda stage, state: any(
                isinstance(f, dict) and str(f.get("severity", "")).lower() == "critical"
                for findings in [
                    state.get("top_actionable_findings", []),
                    state.get("verified_exploits", []),
                    state.get("manual_verification_queue", []),
                ]
                if isinstance(findings, list)
                for f in findings
            ),
            message_template="Critical severity finding discovered at stage: {stage}",
            notification_channels=["webhook", "slack"],
        )
    )

    checker.add_rule(
        PipelineAlertRule(
            name="SCOPE_VIOLATION",
            severity=AlertSeverity.CRITICAL,
            condition=lambda stage, state: bool(state.get("scope_violations")),
            message_template="Scope violation detected at stage: {stage} - {state.get('scope_violations')}",
            notification_channels=["webhook", "slack"],
        )
    )

    checker.add_rule(
        PipelineAlertRule(
            name="PIPELINE_FAILURE",
            severity=AlertSeverity.CRITICAL,
            condition=_check_pipeline_failure,
            message_template="Pipeline stage failed: {stage} - check module_metrics for details",
            notification_channels=["webhook", "slack", "email"],
        )
    )

    checker.add_rule(
        PipelineAlertRule(
            name="TOOL_UNAVAILABLE",
            severity=AlertSeverity.WARNING,
            condition=lambda stage, state: any(
                not ts.get("available", True)
                for ts in state.get("tool_status", {}).values()
                if isinstance(ts, dict)
            ),
            message_template="A configured tool was not found on PATH at stage: {stage}",
            notification_channels=["slack"],
        )
    )

    def _check_recon_coverage(stage: str, state: dict[str, Any]) -> bool:
        subdomains = state.get("subdomains", set())
        if not isinstance(subdomains, (set, list, tuple)):
            return False
        return len(subdomains) < _min_subdomain_threshold

    checker.add_rule(
        PipelineAlertRule(
            name="RECON_COVERAGE_LOW",
            severity=AlertSeverity.WARNING,
            condition=_check_recon_coverage,
            message_template=f"Recon coverage low: subdomain count below {_min_subdomain_threshold} at stage: {{stage}}",
            notification_channels=["slack"],
        )
    )

    register_default_alerts()

    return checker


_pipeline_alert_checker: AlertRuleChecker | None = None


def get_alert_rule_checker() -> AlertRuleChecker:
    """Get or create the global AlertRuleChecker with pipeline rules registered.

    Returns:
        The global AlertRuleChecker instance.
    """
    global _pipeline_alert_checker
    if _pipeline_alert_checker is None:
        _pipeline_alert_checker = register_pipeline_alert_rules()
    return _pipeline_alert_checker


def register_default_alerts(manager=None) -> None:
    """Register pre-configured alerts for pipeline monitoring.

    Creates the following default alert rules:
    - Queue depth exceeds threshold
    - Worker count drops below minimum
    - Error rate exceeds threshold
    - Cache hit rate drops below threshold
    - Memory usage exceeds threshold
    - Response latency exceeds SLA
    - Dead letter queue growing
    - WebSocket connections high

    Args:
        manager: AlertManager to register with. Uses global if None.
    """
    if manager is None:
        manager = get_alert_manager()

    manager.add_rule(
        AlertRule(
            name="queue_depth_high",
            severity=AlertSeverity.WARNING,
            metric_name="cyber_pipeline_queue_depth",
            condition="gt",
            threshold=1000.0,
            for_duration=60.0,
            labels={"team": "pipeline", "component": "queue_system"},
            annotations={
                "message": "Queue depth exceeds 1000 jobs. Processing may be backed up.",
                "runbook": "Check worker health and scale up if needed.",
            },
        )
    )

    manager.add_rule(
        AlertRule(
            name="worker_count_low",
            severity=AlertSeverity.CRITICAL,
            metric_name="cyber_pipeline_active_workers",
            condition="lt",
            threshold=2.0,
            for_duration=30.0,
            labels={"team": "pipeline", "component": "execution_engine"},
            annotations={
                "message": "Active worker count dropped below 2. Job processing is at risk.",
                "runbook": "Check worker processes and restart if necessary.",
            },
        )
    )

    manager.add_rule(
        AlertRule(
            name="error_rate_high",
            severity=AlertSeverity.CRITICAL,
            metric_name="cyber_pipeline_error_rate",
            condition="gt",
            threshold=0.05,
            for_duration=120.0,
            labels={"team": "pipeline", "component": "all"},
            annotations={
                "message": "Error rate exceeds 5%. Pipeline reliability is impacted.",
                "runbook": "Review recent changes and check error logs.",
            },
        )
    )

    manager.add_rule(
        AlertRule(
            name="cache_hit_rate_low",
            severity=AlertSeverity.WARNING,
            metric_name="cyber_pipeline_cache_hit_rate",
            condition="lt",
            threshold=0.5,
            for_duration=300.0,
            labels={"team": "pipeline", "component": "cache_layer"},
            annotations={
                "message": "Cache hit rate dropped below 50%. Performance may be degraded.",
                "runbook": "Check cache backend health and review eviction policies.",
            },
        )
    )

    manager.add_rule(
        AlertRule(
            name="memory_usage_high",
            severity=AlertSeverity.WARNING,
            metric_name="cyber_pipeline_memory_usage_mb",
            condition="gt",
            threshold=4096.0,
            for_duration=60.0,
            labels={"team": "pipeline", "component": "optimized_stages"},
            annotations={
                "message": "Memory usage exceeds 4GB. Risk of OOM.",
                "runbook": "Check for memory leaks and review streaming configurations.",
            },
        )
    )

    manager.add_rule(
        AlertRule(
            name="response_latency_sla_breach",
            severity=AlertSeverity.CRITICAL,
            metric_name="cyber_pipeline_response_time_seconds",
            condition="gt",
            threshold=5.0,
            for_duration=30.0,
            labels={"team": "pipeline", "component": "fastapi_dashboard"},
            annotations={
                "message": "Response latency exceeds 5s SLA. User experience is impacted.",
                "runbook": "Check API performance and database query times.",
            },
        )
    )

    manager.add_rule(
        AlertRule(
            name="dead_letter_queue_growing",
            severity=AlertSeverity.WARNING,
            metric_name="cyber_pipeline_dead_letter_total",
            condition="gt",
            threshold=10.0,
            for_duration=300.0,
            labels={"team": "pipeline", "component": "queue_system"},
            annotations={
                "message": "Dead letter queue has more than 10 jobs. Jobs are failing repeatedly.",
                "runbook": "Review dead letter jobs and fix underlying issues.",
            },
        )
    )

    manager.add_rule(
        AlertRule(
            name="websocket_connections_high",
            severity=AlertSeverity.INFO,
            metric_name="cyber_pipeline_active_connections",
            condition="gt",
            threshold=500.0,
            for_duration=60.0,
            labels={"team": "pipeline", "component": "websocket_server"},
            annotations={
                "message": "WebSocket connections exceed 500. Monitor resource usage.",
                "runbook": "Check connection patterns and consider scaling.",
            },
        )
    )
