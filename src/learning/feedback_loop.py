"""Closed-loop feedback engine for the self-improving pipeline.

Computes scan adaptations based on historical feedback events so that
every scan finding influences subsequent scan configurations, target
prioritization, and payload generation strategies.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from src.learning.telemetry_store import TelemetryStore

logger = logging.getLogger(__name__)


@dataclass
class ExploitTarget:
    """A target queued for active exploitation."""

    endpoint: str
    category: str
    priority: str = "medium"
    chain_findings: list[str] = field(default_factory=list)
    validation_action: str = "validate"


@dataclass
class ScanAdaptation:
    """Directives for adapting the next scan based on feedback."""

    target_boosts: dict[str, float] = field(default_factory=dict)
    target_suppressions: dict[str, float] = field(default_factory=dict)
    plugin_enabled_overrides: dict[str, bool] = field(default_factory=dict)
    plugin_intensity_overrides: dict[str, str] = field(default_factory=dict)
    payload_strategy_updates: dict[str, dict] = field(default_factory=dict)
    threshold_adjustments: dict[str, float] = field(default_factory=dict)
    nuclei_template_boosts: dict[str, float] = field(default_factory=dict)
    active_exploit_queue: list[ExploitTarget] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for integration with pipeline context."""
        return {
            "target_boosts": self.target_boosts,
            "target_suppressions": self.target_suppressions,
            "plugin_enabled_overrides": self.plugin_enabled_overrides,
            "plugin_intensity_overrides": self.plugin_intensity_overrides,
            "payload_strategy_updates": self.payload_strategy_updates,
            "threshold_adjustments": self.threshold_adjustments,
            "nuclei_template_boosts": self.nuclei_template_boosts,
            "active_exploit_queue": [
                {
                    "endpoint": t.endpoint,
                    "category": t.category,
                    "priority": t.priority,
                }
                for t in self.active_exploit_queue
            ],
        }


class FeedbackLoopEngine:
    """Computes scan adaptations from historical feedback.

    Usage:
        engine = FeedbackLoopEngine(store)
        adaptations = engine.compute_adaptations(
            target="example.com",
            mode="deep",
            lookback_runs=10,
        )
        # Apply adaptations to pipeline context
        ctx["scoring"]["target_boosts"] = adaptations.target_boosts
    """

    def __init__(self, store: TelemetryStore):
        self.store = store

    def compute_adaptations(
        self,
        target: str,
        mode: str = "deep",
        lookback_runs: int = 10,
    ) -> ScanAdaptation:
        """Compute adaptations for the next scan.

        Args:
            target: Target name to compute adaptations for.
            mode: Scan mode (fast, deep, idor, ssrf).
            lookback_runs: Number of historical runs to consider.
        """
        runs = self.store.get_recent_runs(target=target, limit=lookback_runs)
        if not runs:
            return ScanAdaptation()

        adaptations = ScanAdaptation()

        # 1. Compute target boosts/suppressions from endpoint feedback
        self._compute_target_adaptations(adaptations, runs)

        # 2. Compute plugin overrides from plugin performance
        self._compute_plugin_adaptations(adaptations, runs)

        # 3. Compute payload strategy updates
        self._compute_payload_adaptations(adaptations, runs)

        # 4. Compute threshold adjustments
        self._compute_threshold_adaptations(adaptations, runs)

        # 5. Compute nuclei template boosts
        self._compute_nuclei_adaptations(adaptations, runs)

        # 6. Queue active exploitation targets
        self._queue_active_exploits(adaptations, runs, mode)

        return adaptations

    def _compute_target_adaptations(
        self, adaptations: ScanAdaptation, runs: list[dict[str, Any]]
    ) -> None:
        """Compute target endpoint boosts and suppressions."""
        # Aggregate feedback by endpoint
        endpoint_stats: dict[str, dict[str, Any]] = {}

        for run in runs:
            events = self.store.get_feedback_events_for_run(run["run_id"])
            for event in events:
                ep = event.get("target_endpoint", "")
                if not ep:
                    continue
                if ep not in endpoint_stats:
                    endpoint_stats[ep] = {
                        "findings": 0,
                        "validated": 0,
                        "fp": 0,
                        "total_weight": 0.0,
                    }
                stats = endpoint_stats[ep]
                stats["findings"] += 1
                if event.get("was_validated") and not event.get("was_false_positive"):
                    stats["validated"] += 1
                if event.get("was_false_positive"):
                    stats["fp"] += 1
                stats["total_weight"] += event.get("feedback_weight", 1.0)

        for ep, stats in endpoint_stats.items():
            total = stats["findings"]
            if total == 0:
                continue

            validation_rate = stats["validated"] / total
            fp_rate = stats["fp"] / total

            if validation_rate > 0.5 and stats["total_weight"] > 2.0:
                # High-value endpoint — boost
                boost = min(10.0, stats["total_weight"] * validation_rate)
                adaptations.target_boosts[ep] = round(boost, 2)
            elif fp_rate > 0.8 and total >= 3:
                # Noisy endpoint — suppress
                suppression = min(-5.0, -stats["total_weight"] * fp_rate)
                adaptations.target_suppressions[ep] = round(suppression, 2)

    def _compute_plugin_adaptations(
        self, adaptations: ScanAdaptation, runs: list[dict[str, Any]]
    ) -> None:
        """Compute plugin enable/disable and intensity overrides."""
        plugin_stats: dict[str, dict[str, int]] = {}

        for run in runs:
            run_plugin_stats = self.store.get_plugin_stats(run["run_id"])
            for ps in run_plugin_stats:
                name = ps.get("plugin_name", "")
                if not name:
                    continue
                if name not in plugin_stats:
                    plugin_stats[name] = {
                        "findings": 0,
                        "tp": 0,
                        "fp": 0,
                        "runs": 0,
                    }
                plugin_stats[name]["findings"] += int(ps.get("findings_produced", 0))
                plugin_stats[name]["tp"] += int(ps.get("true_positives", 0))
                plugin_stats[name]["fp"] += int(ps.get("false_positives", 0))
                plugin_stats[name]["runs"] += 1

        for name, stats in plugin_stats.items():
            if stats["runs"] < 2:
                continue

            precision = stats["tp"] / max(1, stats["tp"] + stats["fp"])

            if precision > 0.7 and stats["findings"] > 5:
                # High-performing plugin — set to aggressive
                adaptations.plugin_intensity_overrides[name] = "aggressive"
            elif precision < 0.2 and stats["findings"] > 10:
                # Very noisy plugin — consider disabling
                adaptations.plugin_intensity_overrides[name] = "light"

    def _compute_payload_adaptations(
        self, adaptations: ScanAdaptation, runs: list[dict[str, Any]]
    ) -> None:
        """Compute payload strategy updates based on historical success."""
        category_stats: dict[str, dict[str, int]] = {}

        for run in runs:
            events = self.store.get_feedback_events_for_run(run["run_id"])
            for event in events:
                cat = event.get("finding_category", "")
                param_type = event.get("parameter_type", "")
                if not cat or not param_type:
                    continue

                key = f"{cat}:{param_type}"
                if key not in category_stats:
                    category_stats[key] = {"success": 0, "total": 0}

                category_stats[key]["total"] += 1
                if event.get("was_validated") and not event.get("was_false_positive"):
                    category_stats[key]["success"] += 1

        for key, stats in category_stats.items():
            if stats["total"] < 3:
                continue

            success_rate = stats["success"] / stats["total"]
            cat, param_type = key.split(":", 1)

            if cat not in adaptations.payload_strategy_updates:
                adaptations.payload_strategy_updates[cat] = {}

            adaptations.payload_strategy_updates[cat][param_type] = round(success_rate, 4)

    def _compute_threshold_adaptations(
        self, adaptations: ScanAdaptation, runs: list[dict[str, Any]]
    ) -> None:
        """Compute threshold adjustments per category."""
        category_stats: dict[str, dict[str, int]] = {}

        for run in runs:
            events = self.store.get_feedback_events_for_run(run["run_id"])
            for event in events:
                cat = event.get("finding_category", "")
                if not cat:
                    continue
                if cat not in category_stats:
                    category_stats[cat] = {"total": 0, "fp": 0}
                category_stats[cat]["total"] += 1
                if event.get("was_false_positive"):
                    category_stats[cat]["fp"] += 1

        for cat, stats in category_stats.items():
            if stats["total"] < 3:
                continue

            fp_rate = stats["fp"] / stats["total"]
            if fp_rate > 0.4:
                # High FP rate — raise thresholds
                adaptations.threshold_adjustments[cat] = round(fp_rate * 0.1, 4)
            elif fp_rate < 0.1 and stats["total"] > 5:
                # Low FP rate — can afford to lower thresholds
                adaptations.threshold_adjustments[cat] = round(-0.02, 4)

    def _compute_nuclei_adaptations(
        self, adaptations: ScanAdaptation, runs: list[dict[str, Any]]
    ) -> None:
        """Compute nuclei template tag boosts."""
        category_boosts: dict[str, float] = {}

        for run in runs:
            events = self.store.get_feedback_events_for_run(run["run_id"])
            for event in events:
                cat = event.get("finding_category", "")
                if not cat:
                    continue
                if event.get("was_validated") and not event.get("was_false_positive"):
                    category_boosts[cat] = category_boosts.get(cat, 0) + event.get(
                        "feedback_weight", 1.0
                    )

        for cat, boost in category_boosts.items():
            if boost > 2.0:
                adaptations.nuclei_template_boosts[cat] = round(min(boost, 5.0), 2)

    def _queue_active_exploits(
        self, adaptations: ScanAdaptation, runs: list[dict[str, Any]], mode: str
    ) -> None:
        """Queue endpoints for active exploitation."""
        # Find high-confidence unvalidated findings
        for run in runs:
            findings = self.store.get_findings_for_run(run["run_id"])
            for finding in findings:
                lifecycle = finding.get("lifecycle_state", "")
                confidence = finding.get("confidence", 0)
                category = finding.get("category", "")

                # Queue for active testing if high confidence but not validated
                if (
                    confidence > 0.7
                    and lifecycle not in ("VALIDATED", "EXPLOITABLE")
                    and category in ("xss", "idor", "ssrf", "sqli", "rce")
                ):
                    adaptations.active_exploit_queue.append(
                        ExploitTarget(
                            endpoint=finding.get("url", ""),
                            category=category,
                            priority="high" if confidence > 0.85 else "medium",
                            validation_action=f"validate_{category}",
                        )
                    )

        # Deduplicate by endpoint
        seen = set()
        deduped = []
        for target in adaptations.active_exploit_queue:
            if target.endpoint not in seen:
                seen.add(target.endpoint)
                deduped.append(target)
        adaptations.active_exploit_queue = deduped[:20]  # Limit to 20
