"""Automatic threshold calibration using PI controller.

Replaces manually tuned detection thresholds with a self-calibrating
system that converges to a target false-positive rate.
"""

import hashlib
import logging
import math
from dataclasses import dataclass
from datetime import UTC, datetime

from src.learning.telemetry_store import TelemetryStore

logger = logging.getLogger(__name__)


@dataclass
class ThresholdConfig:
    """Configurable parameters for threshold auto-tuning."""

    low_threshold: float = 0.45
    medium_threshold: float = 0.58
    high_threshold: float = 0.72
    learning_rate: float = 0.05
    min_threshold: float = 0.20
    max_low_threshold: float = 0.70
    max_medium_threshold: float = 0.80
    max_high_threshold: float = 0.90
    min_gap: float = 0.08
    target_fp_rate: float = 0.15
    fp_rate_tolerance: float = 0.05
    convergence_window: int = 10
    convergence_threshold: float = 0.01
    max_adjustment_per_run: float = 0.05


@dataclass
class ThresholdUpdate:
    """Result of a threshold calibration run."""

    action: str  # "update", "converged", "insufficient_data"
    new_low: float | None = None
    new_medium: float | None = None
    new_high: float | None = None
    is_converged: bool = False
    observed_fp_rate: float | None = None
    error: float | None = None
    adjustment: float | None = None
    reason: str | None = None


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


class ThresholdTuner:
    """Automatically calibrates detection thresholds using PI control."""

    def __init__(
        self,
        store: TelemetryStore,
        config: ThresholdConfig | None = None,
    ):
        self.store = store
        self.config = config or ThresholdConfig()
        self.current_thresholds = {
            "low": self.config.low_threshold,
            "medium": self.config.medium_threshold,
            "high": self.config.high_threshold,
        }
        self._threshold_history: list[dict] = []
        self.is_converged = False
        self.weights = {
            "confidence": 1.65,
            "model_tp": 2.35,
            "model_fp": -1.85,
            "fp_pattern_probability": -2.25,
            "reproducible": 1.10,
        }

    def calibrate(self, run_id: str) -> dict[str, float]:
        """Calibrate thresholds based on recent run outcomes.

        Uses a proportional-integral (PI) controller:
        - If FP rate > target: raise thresholds (fewer findings)
        - If FP rate < target: lower thresholds (more findings)
        """
        runs = self.store.get_recent_runs(limit=20)
        if len(runs) < 3:
            return self.current_thresholds

        # Compute observed FP rate
        total_findings = sum(r.get("total_findings", 0) for r in runs)
        total_fps = sum(r.get("false_positives", 0) for r in runs)

        if total_findings == 0:
            return self.current_thresholds

        observed_fp_rate = total_fps / total_findings

        # PI Controller
        error = observed_fp_rate - self.config.target_fp_rate

        # Proportional term
        p_term = self.config.learning_rate * error

        # Integral term
        integral = sum(
            (r.get("false_positives", 0) / max(1, r.get("total_findings", 1)))
            - self.config.target_fp_rate
            for r in runs
        ) / len(runs)
        i_term = self.config.learning_rate * 0.1 * integral

        # Positive FP error raises thresholds so fewer weak findings reach triage.
        adjustment = p_term + i_term
        adjustment = _clamp(
            adjustment,
            -self.config.max_adjustment_per_run,
            self.config.max_adjustment_per_run,
        )

        # Apply adjustments
        new_low = _clamp(
            self.current_thresholds["low"] + adjustment,
            self.config.min_threshold,
            self.config.max_low_threshold,
        )
        new_medium = _clamp(
            self.current_thresholds["medium"] + adjustment,
            new_low + self.config.min_gap,
            self.config.max_medium_threshold,
        )
        new_high = _clamp(
            self.current_thresholds["high"] + adjustment,
            new_medium + self.config.min_gap,
            self.config.max_high_threshold,
        )

        new_thresholds = {
            "low": round(new_low, 4),
            "medium": round(new_medium, 4),
            "high": round(new_high, 4),
        }

        # Record history
        history_id = f"th-{hashlib.sha256(f'{run_id}'.encode()).hexdigest()[:16]}"
        self._threshold_history.append(
            {
                "run_id": run_id,
                "thresholds": new_thresholds,
                "observed_fp_rate": observed_fp_rate,
                "error": error,
                "adjustment": adjustment,
            }
        )

        # Record to store
        self.store.record_threshold_history(
            {
                "history_id": history_id,
                "run_id": run_id,
                "category": None,
                "low_threshold": new_thresholds["low"],
                "medium_threshold": new_thresholds["medium"],
                "high_threshold": new_thresholds["high"],
                "observed_fp_rate": observed_fp_rate,
                "target_fp_rate": self.config.target_fp_rate,
                "error": round(error, 6),
                "adjustment": round(adjustment, 6),
                "is_converged": False,
                "recorded_at": datetime.now(UTC).isoformat(),
            }
        )

        # Check convergence
        self._check_convergence()

        self.current_thresholds = new_thresholds
        return new_thresholds

    def _check_convergence(self) -> None:
        """Check if thresholds have converged."""
        if len(self._threshold_history) < self.config.convergence_window:
            self.is_converged = False
            return

        recent = self._threshold_history[-self.config.convergence_window :]

        for key in ("low", "medium", "high"):
            values = [h["thresholds"][key] for h in recent]
            max_change = max(values) - min(values)
            if max_change > self.config.convergence_threshold:
                self.is_converged = False
                return

        self.is_converged = True

    def get_thresholds_for_category(
        self,
        category: str,
        category_sensitivity: dict[str, float] | None = None,
    ) -> dict[str, float]:
        """Get category-specific thresholds.

        Applies category sensitivity adjustments on top of calibrated thresholds.
        """
        thresholds = dict(self.current_thresholds)
        sensitivity = (category_sensitivity or {}).get(category, 0.0)

        return {
            "low": max(
                self.config.min_threshold,
                thresholds["low"] + sensitivity,
            ),
            "medium": max(
                thresholds["low"] + self.config.min_gap,
                thresholds["medium"] + sensitivity,
            ),
            "high": max(
                thresholds["medium"] + self.config.min_gap,
                thresholds["high"] + sensitivity,
            ),
        }

    def full_recalibrate(self) -> dict[str, float]:
        """Full recalibration using all historical data."""
        runs = self.store.get_recent_runs(limit=100)
        if len(runs) < 5:
            return self.current_thresholds

        # Compute overall FP rate
        total_findings = sum(r.get("total_findings", 0) for r in runs)
        total_fps = sum(r.get("false_positives", 0) for r in runs)

        if total_findings == 0:
            return self.current_thresholds

        observed_fp_rate = total_fps / total_findings
        error = observed_fp_rate - self.config.target_fp_rate

        # Larger adjustment for full recalibration
        adjustment = error * 0.2
        adjustment = _clamp(adjustment, -0.1, 0.1)

        new_low = _clamp(
            self.config.low_threshold + adjustment,
            self.config.min_threshold,
            self.config.max_low_threshold,
        )
        new_medium = _clamp(
            self.config.medium_threshold + adjustment,
            new_low + self.config.min_gap,
            self.config.max_medium_threshold,
        )
        new_high = _clamp(
            self.config.high_threshold + adjustment,
            new_medium + self.config.min_gap,
            self.config.max_high_threshold,
        )

        self.current_thresholds = {
            "low": round(new_low, 4),
            "medium": round(new_medium, 4),
            "high": round(new_high, 4),
        }

        self._threshold_history.clear()
        self.is_converged = False

        return self.current_thresholds

    def active_learning_weight_update(self, labeled_findings: list[dict[str, Any]]) -> dict[str, float]:
        """Update dynamic heuristic weights vector based on true/false positive feedback loop."""
        if not labeled_findings:
            return self.weights

        lr = getattr(self.config, "learning_rate", 0.05) or 0.05

        for finding in labeled_findings:
            # Extract features
            evidence = finding.get("evidence") or {}
            confidence = max(0.0, min(1.0, float(finding.get("confidence", finding.get("finding_confidence", 0.5)))))
            model_tp = max(0.0, min(1.0, float(finding.get("true_positive_probability", confidence))))
            model_fp = max(0.0, min(1.0, float(finding.get("false_positive_probability", 1.0 - model_tp))))

            # Pattern probability
            fp_prob = 0.0
            status_code = int(finding.get("response_status", evidence.get("response_status", 0)))
            body = str(evidence.get("body_snippet") or evidence.get("response") or "").lower()
            if status_code in {429, 503} and any(i in body for i in ["rate limit", "too many requests"]):
                fp_prob = 0.92
            elif status_code in {403, 406, 418} and any(i in body for i in ["blocked", "waf"]):
                fp_prob = 0.88

            is_reproducible = 1.0 if (evidence.get("reproducible") or evidence.get("confirmed")) else 0.0

            # Compute current feature sum
            feature_sum = -0.85
            feature_sum += self.weights["confidence"] * confidence
            feature_sum += self.weights["model_tp"] * model_tp
            feature_sum += self.weights["model_fp"] * model_fp
            feature_sum += self.weights["fp_pattern_probability"] * fp_prob
            feature_sum += self.weights["reproducible"] * is_reproducible

            # Sigmoid prediction
            if feature_sum >= 0:
                z = math.exp(-feature_sum)
                pred_prob = 1.0 / (1.0 + z)
            else:
                z = math.exp(feature_sum)
                pred_prob = z / (1.0 + z)

            # Determine actual label (1.0 for TP, 0.0 for FP)
            feedback = str(finding.get("feedback") or finding.get("label") or "").lower()
            if feedback in {"tp", "true_positive", "confirmed"}:
                y = 1.0
            elif feedback in {"fp", "false_positive", "suppressed"}:
                y = 0.0
            else:
                is_fp = finding.get("is_false_positive", finding.get("is_fp"))
                if is_fp is not None:
                    y = 0.0 if is_fp else 1.0
                else:
                    y = 1.0 if (evidence.get("confirmed") or evidence.get("reproducible")) else 0.5

            error = y - pred_prob

            # Apply SGD updates
            self.weights["confidence"] += lr * error * confidence
            self.weights["model_tp"] += lr * error * model_tp
            self.weights["model_fp"] += lr * error * model_fp
            self.weights["fp_pattern_probability"] += lr * error * fp_prob
            self.weights["reproducible"] += lr * error * is_reproducible

        logger.info("Active Learning: Updated heuristic weights: %s", self.weights)
        return self.weights
