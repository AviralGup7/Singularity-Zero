"""KPI collection and reporting for the self-improving pipeline.

Computes detection quality, learning progress, efficiency, coverage,
ROI, and reliability metrics from telemetry data.
"""

import math
import statistics
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from src.learning.telemetry_store import TelemetryStore


@dataclass
class RunMetrics:
    """Metrics for a single scan run."""

    run_id: str
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    validated_findings: int = 0
    duration_minutes: float = 0.0
    urls_tested: int = 0
    active_exploits: int = 0
    validation_duration: float | None = None
    time_to_first_finding: float = 0.0


@dataclass
class LearningMetrics:
    """Learning progress metrics."""

    threshold_converged: bool = False
    fp_pattern_count: int = 0
    active_suppression_rules: int = 0
    regression_count: int = 0


@dataclass
class CoverageMetrics:
    """Coverage metrics."""

    endpoint_coverage: float = 0.0
    parameter_coverage: float = 0.0
    category_coverage: float = 0.0
    attack_chain_coverage: float = 0.0
    auto_validated_ratio: float = 0.0
    uptime: float = 1.0
    safety_violations: int = 0


@dataclass
class PipelineKPIs:
    """Complete KPI set for the self-improving pipeline."""

    # Detection quality
    detection_rate: float = 0.0
    precision: float = 0.0
    f1_score: float = 0.0
    fp_rate: float = 0.0
    fn_rate: float = 0.0

    # Learning progress
    learning_velocity_precision: float = 0.0
    learning_velocity_recall: float = 0.0
    threshold_convergence: bool = False
    fp_pattern_count: int = 0
    active_suppression_rules: int = 0

    # Efficiency
    findings_per_scan_hour: float = 0.0
    scan_duration_minutes: float = 0.0
    urls_per_minute: float = 0.0
    active_exploits_per_run: int = 0
    validation_success_rate: float = 0.0

    # Coverage
    endpoint_coverage: float = 0.0
    parameter_coverage: float = 0.0
    category_coverage: float = 0.0
    attack_chain_coverage: float = 0.0

    # ROI
    validated_findings_ratio: float = 0.0
    mean_time_to_detect_minutes: float = 0.0
    mean_time_to_validate_minutes: float = 0.0
    auto_validated_ratio: float = 0.0

    # Reliability
    pipeline_uptime: float = 1.0
    regression_count: int = 0
    safety_violations: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for JSON serialization."""
        return {
            "detection_rate": self.detection_rate,
            "precision": self.precision,
            "f1_score": self.f1_score,
            "fp_rate": self.fp_rate,
            "fn_rate": self.fn_rate,
            "learning_velocity_precision": self.learning_velocity_precision,
            "learning_velocity_recall": self.learning_velocity_recall,
            "threshold_convergence": self.threshold_convergence,
            "fp_pattern_count": self.fp_pattern_count,
            "active_suppression_rules": self.active_suppression_rules,
            "findings_per_scan_hour": self.findings_per_scan_hour,
            "scan_duration_minutes": self.scan_duration_minutes,
            "urls_per_minute": self.urls_per_minute,
            "active_exploits_per_run": self.active_exploits_per_run,
            "validation_success_rate": self.validation_success_rate,
            "endpoint_coverage": self.endpoint_coverage,
            "parameter_coverage": self.parameter_coverage,
            "category_coverage": self.category_coverage,
            "attack_chain_coverage": self.attack_chain_coverage,
            "validated_findings_ratio": self.validated_findings_ratio,
            "mean_time_to_detect_minutes": self.mean_time_to_detect_minutes,
            "mean_time_to_validate_minutes": self.mean_time_to_validate_minutes,
            "auto_validated_ratio": self.auto_validated_ratio,
            "pipeline_uptime": self.pipeline_uptime,
            "regression_count": self.regression_count,
            "safety_violations": self.safety_violations,
        }


def _compute_slope(x: list[int], y: list[float]) -> float:
    """Compute linear regression slope."""
    n = len(x)
    if n < 2:
        return 0.0
    mean_x = sum(x) / n
    mean_y = sum(y) / n
    numerator = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, y))
    denominator = sum((xi - mean_x) ** 2 for xi in x)
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _normalize_slope(slope: float) -> float:
    """Normalize a slope to -1 to +1 range using tanh."""
    return math.tanh(slope * 100)


class MetricsCollector:
    """Collects and computes pipeline KPIs from telemetry data."""

    def __init__(self, store: TelemetryStore):
        self.store = store

    def compute_kpis(self, target: str | None = None) -> PipelineKPIs:
        """Compute all KPIs from telemetry data.

        Args:
            target: Optional target name to filter metrics for.
        """
        runs = self.store.get_recent_runs(target=target, limit=100)
        if not runs:
            return PipelineKPIs()

        run_metrics = []
        for run in runs:
            rm = self._compute_run_metrics(run)
            run_metrics.append(rm)

        # Aggregate detection metrics
        total_tp = sum(r.true_positives for r in run_metrics)
        total_fp = sum(r.false_positives for r in run_metrics)
        total_fn = sum(r.false_negatives for r in run_metrics)

        detection_rate = total_tp / max(1, total_tp + total_fn)
        precision = total_tp / max(1, total_tp + total_fp)
        f1 = 2 * precision * detection_rate / max(0.001, precision + detection_rate)
        fp_rate = total_fp / max(1, total_tp + total_fp)
        fn_rate = total_fn / max(1, total_tp + total_fn)

        # Learning velocity
        recent = run_metrics[-10:]
        if len(recent) >= 3:
            x = list(range(len(recent)))
            precisions = [
                r.true_positives / max(1, r.true_positives + r.false_positives) for r in recent
            ]
            recalls = [
                r.true_positives / max(1, r.true_positives + r.false_negatives) for r in recent
            ]
            lv_precision = _compute_slope(x, precisions)
            lv_recall = _compute_slope(x, recalls)
        else:
            lv_precision = 0.0
            lv_recall = 0.0

        # Efficiency
        total_duration_hours = sum(r.duration_minutes for r in run_metrics) / 60
        total_findings = sum(r.total_findings for r in run_metrics)
        findings_per_hour = total_findings / max(0.01, total_duration_hours)
        avg_duration = (
            statistics.mean(r.duration_minutes for r in run_metrics) if run_metrics else 0
        )
        urls_per_min = (
            statistics.mean(r.urls_tested / max(1, r.duration_minutes) for r in run_metrics)
            if run_metrics
            else 0
        )

        # Validation
        total_validated = sum(r.validated_findings for r in run_metrics)
        validation_success = total_validated / max(1, total_findings)

        # Learning metrics
        learning = self._compute_learning_metrics()

        # Coverage
        coverage = self._compute_coverage_metrics(runs)

        return PipelineKPIs(
            detection_rate=round(detection_rate, 4),
            precision=round(precision, 4),
            f1_score=round(f1, 4),
            fp_rate=round(fp_rate, 4),
            fn_rate=round(fn_rate, 4),
            learning_velocity_precision=round(lv_precision, 6),
            learning_velocity_recall=round(lv_recall, 6),
            threshold_convergence=learning.threshold_converged,
            fp_pattern_count=learning.fp_pattern_count,
            active_suppression_rules=learning.active_suppression_rules,
            findings_per_scan_hour=round(findings_per_hour, 1),
            scan_duration_minutes=round(avg_duration, 1),
            urls_per_minute=round(urls_per_min, 0),
            active_exploits_per_run=int(
                statistics.mean(r.active_exploits for r in run_metrics) if run_metrics else 0
            ),
            validation_success_rate=round(validation_success, 4),
            endpoint_coverage=coverage.endpoint_coverage,
            parameter_coverage=coverage.parameter_coverage,
            category_coverage=coverage.category_coverage,
            attack_chain_coverage=coverage.attack_chain_coverage,
            validated_findings_ratio=round(validation_success, 4),
            mean_time_to_detect_minutes=round(
                statistics.mean(r.time_to_first_finding for r in run_metrics)
                if run_metrics and any(r.time_to_first_finding for r in run_metrics)
                else 0,
                1,
            ),
            mean_time_to_validate_minutes=round(
                statistics.mean(r.validation_duration for r in run_metrics if r.validation_duration)
                if run_metrics and any(r.validation_duration for r in run_metrics)
                else 0,
                1,
            ),
            auto_validated_ratio=coverage.auto_validated_ratio,
            pipeline_uptime=coverage.uptime,
            regression_count=learning.regression_count,
            safety_violations=coverage.safety_violations,
        )

    def _compute_run_metrics(self, run: dict) -> RunMetrics:
        """Compute metrics for a single run."""
        findings = self.store.get_findings_for_run(run["run_id"])

        tp = 0
        fp = 0
        fn = 0
        validated = 0

        for f in findings:
            lifecycle = f.get("lifecycle_state", "")
            decision = f.get("decision", "")
            confidence = f.get("confidence", 0)

            if lifecycle in ("VALIDATED", "EXPLOITABLE", "REPORTABLE"):
                tp += 1
                validated += 1
            elif decision == "DROP":
                fp += 1
            elif confidence > 0.6 and decision in ("HIGH", "MEDIUM"):
                tp += 1
            else:
                fp += 1

        duration = 0.0
        if run.get("start_time") and run.get("end_time"):
            try:
                start = datetime.fromisoformat(run["start_time"])
                end = datetime.fromisoformat(run["end_time"])
                duration = (end - start).total_seconds() / 60
            except (ValueError, TypeError):
                duration = run.get("scan_duration_sec", 0) / 60

        return RunMetrics(
            run_id=run["run_id"],
            total_findings=len(findings),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            validated_findings=validated,
            duration_minutes=duration,
            urls_tested=run.get("total_urls", 0),
        )

    def _compute_learning_metrics(self) -> LearningMetrics:
        """Compute learning progress metrics."""
        fp_count = self.store.get_active_fp_pattern_count()

        # Check threshold convergence
        history = self.store.get_threshold_history()
        converged = False
        if len(history) >= 10:
            recent = history[:10]
            for key in ("low_threshold", "medium_threshold", "high_threshold"):
                values = [h.get(key, 0) for h in recent if h.get(key) is not None]
                if len(values) >= 3:
                    max_change = max(values) - min(values)
                    if max_change > 0.01:
                        break
            else:
                converged = True

        return LearningMetrics(
            threshold_converged=converged,
            fp_pattern_count=fp_count,
            active_suppression_rules=fp_count,  # Each active FP pattern is a suppression rule
        )

    def _compute_coverage_metrics(self, runs: list[dict]) -> CoverageMetrics:
        """Compute coverage metrics."""
        if not runs:
            return CoverageMetrics()

        # Count unique categories with findings
        all_findings = []
        for run in runs:
            all_findings.extend(self.store.get_findings_for_run(run["run_id"]))

        categories_with_findings = set(f.get("category") for f in all_findings if f.get("category"))
        total_known_categories = 42  # OWASP + custom categories
        category_coverage = len(categories_with_findings) / max(1, total_known_categories)

        # Uptime: fraction of runs that completed successfully
        completed = sum(1 for r in runs if r.get("status") == "completed")
        uptime = completed / max(1, len(runs))

        return CoverageMetrics(
            category_coverage=round(category_coverage, 4),
            uptime=round(uptime, 4),
        )

    def record_learning_cycle(self, report: Any) -> None:
        """Record a learning cycle completion as metrics.

        Args:
            report: LearningReport object from the learning loop.
        """
        import logging

        logger = logging.getLogger(__name__)
        if report is None:
            logger.warning("Received None report, skipping metrics recording")
            return
        try:
            report_data = (
                report.model_dump()
                if hasattr(report, "model_dump")
                else dict(report)
                if hasattr(report, "__dict__")
                else {}
            )
            if report_data.get("run_id"):
                logger.info(
                    "Learning cycle %s recorded: precision=%.4f, recall=%.4f, fp_rate=%.4f",
                    report_data.get("run_id", "unknown"),
                    report_data.get("precision", 0),
                    report_data.get("recall", 0),
                    report_data.get("false_positive_rate", 0),
                )
        except Exception as exc:
            logger.debug("Failed to record learning cycle metrics: %s", exc)
