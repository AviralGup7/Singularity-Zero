"""Automatic threshold calibration using PI controller.

Replaces manually tuned detection thresholds with a self-calibrating
system that converges to a target false-positive rate.
"""

import hashlib
import logging
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

        # Total adjustment (negative because high FP → raise thresholds)
        adjustment = -(p_term + i_term)
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
        adjustment = -error * 0.2
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
