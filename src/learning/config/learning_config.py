"""Configuration for the self-improving learning subsystems.

Provides typed configuration classes for all learning components
with sensible defaults and validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FeedbackConfig:
    """Configuration for the feedback loop engine."""

    decay_rate: float = 0.01
    lookback_runs: int = 10
    max_adaptation_weight: float = 2.0


@dataclass
class RiskRankingConfig:
    """Configuration for the adaptive risk-ranking engine."""

    exploration_parameter: float = 0.5
    min_prior_probability: float = 0.001
    blend_factor_initial: float = 0.0
    blend_factor_growth_rate: float = 0.05


@dataclass
class FPTrackingConfig:
    """Configuration for the FP tracking subsystem."""

    target_fp_rate: float = 0.15
    fp_rate_tolerance: float = 0.05
    learning_rate: float = 0.05
    convergence_window: int = 10
    min_pattern_occurrences: int = 3


@dataclass
class ThresholdTuningConfig:
    """Configuration for the threshold auto-tuner."""

    learning_rate: float = 0.05
    integral_gain: float = 0.005
    max_adjustment_per_run: float = 0.05
    min_threshold: float = 0.20
    convergence_threshold: float = 0.01


@dataclass
class ActiveExploitationConfig:
    """Configuration for active exploitation."""

    enabled: bool = True
    max_depth: int = 2
    max_concurrent: int = 3
    max_per_run: int = 50
    requires_approval_for_depth: list[int] = field(default_factory=lambda: [3, 4])


@dataclass
class SafetyConfig:
    """Safety guardrail configuration."""

    max_requests_per_second: float = 5.0
    max_requests_per_session: int = 100
    cooldown_between_exploits_sec: float = 2.0
    blocked_paths: list[str] = field(
        default_factory=lambda: [
            "/admin/delete",
            "/api/payments/execute",
            "/api/users/*/delete",
            "/api/orders/cancel",
        ]
    )
    blocked_payload_patterns: list[str] = field(
        default_factory=lambda: [
            "DROP TABLE",
            "DELETE FROM",
            "rm -rf",
            "shutdown",
            "format",
        ]
    )


@dataclass
class RetentionConfig:
    """Data retention policy configuration."""

    findings_days: int = 730
    feedback_days: int = 365
    risk_scores_days: int = 180
    graph_edges_days: int = 180
    plugin_stats_days: int = 365
    performance_metrics_days: int = 730
    session_state_days: int = 30
    attack_chain_days: int = 365


@dataclass
class LearningConfig:
    """Top-level configuration for the learning subsystem."""

    enabled: bool = True
    database_path: str = ".pipeline/telemetry.db"
    update_mode: str = "hybrid"  # online, batch, hybrid
    batch_retrain_interval: int = 50

    feedback: FeedbackConfig = field(default_factory=FeedbackConfig)
    risk_ranking: RiskRankingConfig = field(default_factory=RiskRankingConfig)
    fp_tracking: FPTrackingConfig = field(default_factory=FPTrackingConfig)
    threshold_tuning: ThresholdTuningConfig = field(default_factory=ThresholdTuningConfig)
    active_exploitation: ActiveExploitationConfig = field(default_factory=ActiveExploitationConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LearningConfig:
        """Create config from a dictionary (e.g., JSON config)."""
        config = cls()

        if "enabled" in data:
            config.enabled = bool(data["enabled"])
        if "database_path" in data:
            config.database_path = str(data["database_path"])
        if "update_mode" in data:
            config.update_mode = str(data["update_mode"])
        if "batch_retrain_interval" in data:
            config.batch_retrain_interval = int(data["batch_retrain_interval"])

        if "feedback" in data and isinstance(data["feedback"], dict):
            fb = data["feedback"]
            config.feedback = FeedbackConfig(
                decay_rate=float(fb.get("decay_rate", 0.01)),
                lookback_runs=int(fb.get("lookback_runs", 10)),
                max_adaptation_weight=float(fb.get("max_adaptation_weight", 2.0)),
            )

        if "risk_ranking" in data and isinstance(data["risk_ranking"], dict):
            rr = data["risk_ranking"]
            config.risk_ranking = RiskRankingConfig(
                exploration_parameter=float(rr.get("exploration_parameter", 0.5)),
                min_prior_probability=float(rr.get("min_prior_probability", 0.001)),
                blend_factor_initial=float(rr.get("blend_factor_initial", 0.0)),
                blend_factor_growth_rate=float(rr.get("blend_factor_growth_rate", 0.05)),
            )

        if "fp_tracking" in data and isinstance(data["fp_tracking"], dict):
            fp = data["fp_tracking"]
            config.fp_tracking = FPTrackingConfig(
                target_fp_rate=float(fp.get("target_fp_rate", 0.15)),
                fp_rate_tolerance=float(fp.get("fp_rate_tolerance", 0.05)),
                learning_rate=float(fp.get("learning_rate", 0.05)),
                convergence_window=int(fp.get("convergence_window", 10)),
                min_pattern_occurrences=int(fp.get("min_pattern_occurrences", 3)),
            )

        if "threshold_tuning" in data and isinstance(data["threshold_tuning"], dict):
            tt = data["threshold_tuning"]
            config.threshold_tuning = ThresholdTuningConfig(
                learning_rate=float(tt.get("learning_rate", 0.05)),
                integral_gain=float(tt.get("integral_gain", 0.005)),
                max_adjustment_per_run=float(tt.get("max_adjustment_per_run", 0.05)),
                min_threshold=float(tt.get("min_threshold", 0.20)),
                convergence_threshold=float(tt.get("convergence_threshold", 0.01)),
            )

        if "retention" in data and isinstance(data["retention"], dict):
            ret = data["retention"]
            config.retention = RetentionConfig(
                findings_days=int(ret.get("findings_days", 730)),
                feedback_days=int(ret.get("feedback_days", 365)),
                risk_scores_days=int(ret.get("risk_scores_days", 180)),
                graph_edges_days=int(ret.get("graph_edges_days", 180)),
                plugin_stats_days=int(ret.get("plugin_stats_days", 365)),
                performance_metrics_days=int(ret.get("performance_metrics_days", 730)),
                session_state_days=int(ret.get("session_state_days", 30)),
                attack_chain_days=int(ret.get("attack_chain_days", 365)),
            )

        return config

    @property
    def db_path(self) -> Path:
        """Get the database path as a Path object."""
        return Path(self.database_path)
