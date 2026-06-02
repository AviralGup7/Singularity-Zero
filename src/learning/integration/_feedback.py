from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.learning.integration import LearningIntegration

logger = logging.getLogger(__name__)


def emit_feedback_events(
    integration: LearningIntegration,
    ctx: dict[str, Any],
    findings: list[dict[str, Any]],
) -> int:
    """Convert merged findings into feedback events.

    Call this after findings are merged and classified.
    Returns the number of events emitted.
    """
    from src.learning.models.feedback_event import FeedbackEvent

    if not integration.config.enabled or not findings:
        return 0

    run_id = ctx.get("run_id", "")
    if not run_id:
        return 0

    count = 0
    for finding in findings:
        try:
            event = FeedbackEvent.from_finding(finding, run_id, ctx)
            row = {
                "event_id": event.event_id,
                "run_id": event.run_id,
                "timestamp": event.timestamp.isoformat(),
                "target_host": event.target_host,
                "target_endpoint": event.target_endpoint,
                "finding_category": event.finding_category,
                "finding_severity": event.finding_severity,
                "finding_confidence": event.finding_confidence,
                "finding_decision": event.finding_decision,
                "plugin_name": event.plugin_name,
                "parameter_name": event.parameter_name,
                "parameter_type": event.parameter_type,
                "was_validated": event.was_validated,
                "was_false_positive": event.was_false_positive,
                "validation_method": event.validation_method,
                "response_delta_score": event.response_delta_score,
                "endpoint_type": event.endpoint_type,
                "tech_stack": event.tech_stack,
                "scan_mode": event.scan_mode,
                "feedback_weight": event.feedback_weight,
            }
            integration.store.insert_feedback_event(row)
            count += 1
        except Exception:
            logger.debug("Failed to emit feedback event for finding", exc_info=True)

    if count > 0:
        logger.info("Emitted %d feedback events for run %s", count, run_id)

    return count


def record_scan_run(
    integration: LearningIntegration,
    ctx: dict[str, Any],
) -> None:
    """Record the scan run metadata."""
    if not integration.config.enabled:
        return

    run_id = ctx.get("run_id", "")
    if not run_id:
        return

    urls = ctx.get("urls", set())
    priority_urls = ctx.get("priority_urls", [])
    findings = ctx.get("reportable_findings", [])

    validated = sum(1 for f in findings if f.get("lifecycle_state") in ("VALIDATED", "EXPLOITABLE"))
    fps = sum(1 for f in findings if f.get("decision") == "DROP")

    duration = 0.0
    start = ctx.get("start_time")
    end = ctx.get("end_time")
    if start and end:
        try:
            if isinstance(start, str):
                start = datetime.fromisoformat(start)
            if isinstance(end, str):
                end = datetime.fromisoformat(end)
            duration = (end - start).total_seconds()
        except (ValueError, TypeError) as exc:
            logger.warning(
                "Failed to parse scan start/end timestamps (%s, %s): %s. scan_duration_sec defaults to 0.0.",
                start,
                end,
                exc,
            )

    row = {
        "run_id": run_id,
        "target_name": ctx.get("target_name", ""),
        "mode": ctx.get("mode", "deep"),
        "start_time": start.isoformat() if isinstance(start, datetime) else str(start),
        "end_time": end.isoformat() if isinstance(end, datetime) else str(end),
        "status": ctx.get("status", "completed"),
        "total_urls": len(urls) if isinstance(urls, (set, list)) else 0,
        "total_endpoints": len(priority_urls) if isinstance(priority_urls, (list, set)) else 0,
        "total_findings": len(findings),
        "validated_findings": validated,
        "false_positives": fps,
        "scan_duration_sec": duration,
        "config_hash": ctx.get("config_hash", ""),
        "feedback_applied": ctx.get("feedback_applied", False),
    }
    integration.store.record_scan_run(row)


def record_plugin_stats(
    integration: LearningIntegration,
    ctx: dict[str, Any],
) -> None:
    """Record plugin execution statistics."""
    run_id = ctx.get("run_id", "")
    if not run_id:
        return

    module_metrics = ctx.get("module_metrics", {})
    for plugin_name, metrics in module_metrics.items():
        if not isinstance(metrics, dict):
            continue

        findings_produced = metrics.get("findings", 0)
        if findings_produced == 0:
            continue

        # Estimate TP/FP from module-level confidence
        plugin_findings = [
            f for f in ctx.get("reportable_findings", []) if f.get("module") == plugin_name
        ]
        tp = sum(
            1 for f in plugin_findings if f.get("lifecycle_state") in ("VALIDATED", "EXPLOITABLE")
        )
        fp = sum(1 for f in plugin_findings if f.get("decision") == "DROP")

        precision = tp / max(1, tp + fp)
        fn = max(0, findings_produced - tp)
        recall = tp / max(1, tp + fn)

        stat_id = f"ps-{hashlib.sha256(f'{run_id}:{plugin_name}'.encode()).hexdigest()[:16]}"

        integration.store.record_plugin_stat(
            {
                "stat_id": stat_id,
                "run_id": run_id,
                "plugin_name": plugin_name,
                "findings_produced": findings_produced,
                "true_positives": tp,
                "false_positives": fp,
                "execution_time_ms": metrics.get("duration_ms", 0),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "recorded_at": datetime.now(UTC).isoformat(),
            }
        )
