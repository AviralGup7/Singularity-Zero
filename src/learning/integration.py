"""Integration hooks for connecting the learning subsystem to the pipeline.

Provides functions that can be called from the PipelineOrchestrator
to record telemetry, compute adaptations, and apply learning-driven
changes to the pipeline context.

Usage in PipelineOrchestrator:
    from src.learning.integration import LearningIntegration

    integration = LearningIntegration.get_or_create(ctx)

    # After findings are merged (Hook 2)
    integration.emit_feedback_events(ctx)

    # After reporting (Hook 3)
    await integration.run_learning_update(ctx)

    # Before next run (Hook 1)
    adaptations = integration.compute_adaptations(ctx)
    integration.apply_adaptations(ctx, adaptations)
"""

from __future__ import annotations

import atexit
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.learning.config import LearningConfig
from src.learning.feedback_loop import FeedbackLoopEngine
from src.learning.fp_tracker import FPTracker
from src.learning.metrics import MetricsCollector, PipelineKPIs
from src.learning.telemetry_store import TelemetryStore
from src.learning.threshold_tuner import ThresholdConfig, ThresholdTuner

logger = logging.getLogger(__name__)

# Global singleton for the integration instance
_integration_instance: LearningIntegration | None = None


def _resolve_db_path(config_path: str | None = None) -> Path:
    """Resolve the telemetry database path."""
    if config_path:
        return Path(config_path)
    return Path(".pipeline") / "telemetry.db"


class LearningIntegration:
    """Bridges the learning subsystem with the pipeline orchestrator."""

    def __init__(
        self,
        store: TelemetryStore,
        config: LearningConfig | None = None,
    ):
        self.store = store
        self.config = config or LearningConfig()
        self._feedback_engine = FeedbackLoopEngine(store)
        self._fp_tracker = FPTracker(store)
        self._metrics = MetricsCollector(store)
        self._threshold_tuner = ThresholdTuner(
            store,
            ThresholdConfig(
                learning_rate=self.config.threshold_tuning.learning_rate,
                max_adjustment_per_run=self.config.threshold_tuning.max_adjustment_per_run,
                min_threshold=self.config.threshold_tuning.min_threshold,
                target_fp_rate=self.config.fp_tracking.target_fp_rate,
                convergence_window=self.config.fp_tracking.convergence_window,
                convergence_threshold=self.config.threshold_tuning.convergence_threshold,
            ),
        )

    @classmethod
    def get_or_create(
        cls,
        ctx: dict[str, Any] | None = None,
        config: LearningConfig | None = None,
    ) -> LearningIntegration:
        """Get or create the global integration instance.

        Args:
            ctx: Pipeline context dict. May contain learning config.
            config: Explicit learning config. Overrides ctx config.
        """
        global _integration_instance

        if _integration_instance is not None:
            return _integration_instance

        # Load config from pipeline context if available
        if ctx and not config:
            learning_cfg = ctx.get("learning", {})
            if learning_cfg:
                config = LearningConfig.from_dict(learning_cfg)

        if not config:
            config = LearningConfig()

        if not config.enabled:
            # Return a no-op instance
            store = TelemetryStore(_resolve_db_path())
            store.initialize()
            _integration_instance = cls(store, config)
            return _integration_instance

        db_path = _resolve_db_path(config.database_path)
        store = TelemetryStore(db_path)
        store.initialize()

        _integration_instance = cls(store, config)
        return _integration_instance

    @classmethod
    def reset(cls) -> None:
        """Reset the global instance (useful for testing)."""
        global _integration_instance
        if _integration_instance is not None:
            _integration_instance.store.close()
        _integration_instance = None

    # ------------------------------------------------------------------
    # Hook 1: Pre-Scan Adaptation
    # ------------------------------------------------------------------

    def compute_adaptations(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """Compute feedback-driven adaptations before a scan begins.

        Call this at the start of PipelineOrchestrator.run() to apply
        learning from previous runs.
        """
        if not self.config.enabled:
            return {}

        target = ctx.get("target_name", "")
        mode = ctx.get("mode", "deep")
        lookback = self.config.feedback.lookback_runs

        adaptations = self._feedback_engine.compute_adaptations(
            target=target,
            mode=mode,
            lookback_runs=lookback,
        )

        return adaptations.to_dict()

    def apply_adaptations(
        self,
        ctx: dict[str, Any],
        adaptations: dict[str, Any],
    ) -> None:
        """Apply computed adaptations to the pipeline context.

        Modifies ctx in-place to apply learning-driven changes.
        """
        if not adaptations:
            return

        # Apply target boosts to scoring config
        if "target_boosts" in adaptations:
            scoring = ctx.setdefault("scoring", {})
            scoring["target_boosts"] = adaptations["target_boosts"]
            scoring["target_suppressions"] = adaptations.get("target_suppressions", {})

        # Apply plugin overrides
        if "plugin_enabled_overrides" in adaptations:
            analysis = ctx.setdefault("analysis", {})
            analysis["plugin_overrides"] = adaptations["plugin_enabled_overrides"]

        if "plugin_intensity_overrides" in adaptations:
            analysis = ctx.setdefault("analysis", {})
            analysis["plugin_intensity"] = adaptations["plugin_intensity_overrides"]

        # Apply threshold adjustments
        if "threshold_adjustments" in adaptations:
            decision = ctx.setdefault("decision", {})
            decision["threshold_deltas"] = adaptations["threshold_adjustments"]

        # Apply nuclei template boosts
        if "nuclei_template_boosts" in adaptations:
            ctx["nuclei_template_boosts"] = adaptations["nuclei_template_boosts"]

        # Queue active exploitation targets
        if "active_exploit_queue" in adaptations:
            ctx["active_exploit_queue"] = adaptations["active_exploit_queue"]

        logger.info(
            "Applied learning adaptations: %d target boosts, %d plugin overrides, "
            "%d threshold adjustments, %d exploit targets",
            len(adaptations.get("target_boosts", {})),
            len(adaptations.get("plugin_enabled_overrides", {})),
            len(adaptations.get("threshold_adjustments", {})),
            len(adaptations.get("active_exploit_queue", [])),
        )

    # ------------------------------------------------------------------
    # Hook 2: Post-Finding Processing
    # ------------------------------------------------------------------

    def emit_feedback_events(
        self,
        ctx: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> int:
        """Convert merged findings into feedback events.

        Call this after findings are merged and classified.
        Returns the number of events emitted.
        """
        if not self.config.enabled or not findings:
            return 0

        run_id = ctx.get("run_id", "")
        if not run_id:
            return 0

        count = 0
        for finding in findings:
            try:
                from src.learning.models.feedback_event import FeedbackEvent

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
                self.store.insert_feedback_event(row)
                count += 1
            except Exception:
                logger.debug("Failed to emit feedback event for finding", exc_info=True)

        if count > 0:
            logger.info("Emitted %d feedback events for run %s", count, run_id)

        return count

    def record_scan_run(self, ctx: dict[str, Any]) -> None:
        """Record the scan run metadata."""
        if not self.config.enabled:
            return

        run_id = ctx.get("run_id", "")
        if not run_id:
            return

        urls = ctx.get("urls", set())
        priority_urls = ctx.get("priority_urls", [])
        findings = ctx.get("reportable_findings", [])

        validated = sum(
            1 for f in findings if f.get("lifecycle_state") in ("VALIDATED", "EXPLOITABLE")
        )
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
            except ValueError, TypeError:
                pass

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
        self.store.record_scan_run(row)

    # ------------------------------------------------------------------
    # Hook 3: Post-Scan Learning Update
    # ------------------------------------------------------------------

    async def run_learning_update(self, ctx: dict[str, Any]) -> dict[str, Any]:
        """Execute the full learning cycle after a pipeline run.

        Call this at the end of PipelineOrchestrator.run(), after all
        findings have been collected and reported.
        """
        if not self.config.enabled:
            return {"status": "disabled"}

        run_id = ctx.get("run_id", "")
        findings = ctx.get("reportable_findings", [])
        result: dict[str, Any] = {"run_id": run_id, "status": "completed"}

        # Phase 1: Record telemetry
        self.record_scan_run(ctx)
        events_emitted = self.emit_feedback_events(ctx, findings)
        result["feedback_events_emitted"] = events_emitted

        # Phase 2: Recompute feedback weights
        if run_id:
            updated = self.store.recompute_feedback_weights(
                run_id, decay_rate=self.config.feedback.decay_rate
            )
            result["feedback_weights_recomputed"] = updated

        # Phase 3: Update FP patterns
        fp_updated = await self._fp_tracker.update_from_run(run_id)
        result["fp_patterns_updated"] = fp_updated

        # Phase 4: Calibrate thresholds
        if run_id:
            new_thresholds = self._threshold_tuner.calibrate(run_id)
            result["thresholds"] = new_thresholds
            result["thresholds_converged"] = self._threshold_tuner.is_converged

        # Phase 5: Record plugin stats
        self._record_plugin_stats(ctx)

        # Phase 6: Compute KPIs
        try:
            kpis = self._metrics.compute_kpis(target=ctx.get("target_name"))
            result["kpis"] = kpis.to_dict()
        except Exception:
            logger.debug("Failed to compute KPIs", exc_info=True)
            result["kpis"] = {}

        logger.info(
            "Learning update complete for run %s: %d events, %d FP patterns, converged=%s",
            run_id,
            events_emitted,
            fp_updated,
            self._threshold_tuner.is_converged,
        )

        return result

    def _record_plugin_stats(self, ctx: dict[str, Any]) -> None:
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
                1
                for f in plugin_findings
                if f.get("lifecycle_state") in ("VALIDATED", "EXPLOITABLE")
            )
            fp = sum(1 for f in plugin_findings if f.get("decision") == "DROP")

            precision = tp / max(1, tp + fp)
            fn = max(0, findings_produced - tp)
            recall = tp / max(1, tp + fn)

            import hashlib

            stat_id = f"ps-{hashlib.sha256(f'{run_id}:{plugin_name}'.encode()).hexdigest()[:16]}"

            self.store.record_plugin_stat(
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

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def get_kpis(self, target: str | None = None) -> PipelineKPIs:
        """Get current pipeline KPIs."""
        return self._metrics.compute_kpis(target=target)

    def get_db_size(self) -> dict[str, int]:
        """Get database size information."""
        return self.store.get_db_size()

    def close(self) -> None:
        """Close the telemetry store."""
        self.store.close()


def _cleanup_learning_integration() -> None:
    """Close the global learning integration store on interpreter shutdown."""
    global _integration_instance
    if _integration_instance is not None:
        _integration_instance.close()
        _integration_instance = None


atexit.register(_cleanup_learning_integration)
