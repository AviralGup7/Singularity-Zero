"""Tests for the learning configuration classes."""

from pathlib import Path

from src.learning.config.learning_config import (
    ActiveExploitationConfig,
    FeedbackConfig,
    FPTrackingConfig,
    LearningConfig,
    RetentionConfig,
    RiskRankingConfig,
    SafetyConfig,
    ThresholdTuningConfig,
)


class TestFeedbackConfig:
    def test_defaults(self):
        cfg = FeedbackConfig()
        assert cfg.decay_rate == 0.01
        assert cfg.lookback_runs == 10
        assert cfg.max_adaptation_weight == 2.0


class TestRiskRankingConfig:
    def test_defaults(self):
        cfg = RiskRankingConfig()
        assert cfg.exploration_parameter == 0.5
        assert cfg.min_prior_probability == 0.001
        assert cfg.blend_factor_initial == 0.0
        assert cfg.blend_factor_growth_rate == 0.05


class TestFPTrackingConfig:
    def test_defaults(self):
        cfg = FPTrackingConfig()
        assert cfg.target_fp_rate == 0.15
        assert cfg.fp_rate_tolerance == 0.05
        assert cfg.learning_rate == 0.05
        assert cfg.convergence_window == 10
        assert cfg.min_pattern_occurrences == 3


class TestThresholdTuningConfig:
    def test_defaults(self):
        cfg = ThresholdTuningConfig()
        assert cfg.learning_rate == 0.05
        assert cfg.integral_gain == 0.005
        assert cfg.max_adjustment_per_run == 0.05
        assert cfg.min_threshold == 0.20
        assert cfg.convergence_threshold == 0.01


class TestActiveExploitationConfig:
    def test_defaults(self):
        cfg = ActiveExploitationConfig()
        assert cfg.enabled is True
        assert cfg.max_depth == 2
        assert cfg.max_concurrent == 3
        assert cfg.max_per_run == 50
        assert cfg.requires_approval_for_depth == [3, 4]

    def test_disabled(self):
        cfg = ActiveExploitationConfig(enabled=False)
        assert cfg.enabled is False


class TestSafetyConfig:
    def test_defaults(self):
        cfg = SafetyConfig()
        assert cfg.max_requests_per_second == 5.0
        assert cfg.max_requests_per_session == 100
        assert cfg.cooldown_between_exploits_sec == 2.0
        assert "/admin/delete" in cfg.blocked_paths
        assert "DROP TABLE" in cfg.blocked_payload_patterns

    def test_custom_blocked_paths(self):
        cfg = SafetyConfig(blocked_paths=["/secret"])
        assert cfg.blocked_paths == ["/secret"]


class TestRetentionConfig:
    def test_defaults(self):
        cfg = RetentionConfig()
        assert cfg.findings_days == 730
        assert cfg.feedback_days == 365
        assert cfg.risk_scores_days == 180
        assert cfg.graph_edges_days == 180
        assert cfg.plugin_stats_days == 365
        assert cfg.performance_metrics_days == 730
        assert cfg.session_state_days == 30
        assert cfg.attack_chain_days == 365


class TestLearningConfig:
    def test_defaults(self):
        cfg = LearningConfig()
        assert cfg.enabled is True
        assert cfg.database_path == ".pipeline/telemetry.db"
        assert cfg.update_mode == "hybrid"
        assert cfg.batch_retrain_interval == 50
        assert isinstance(cfg.feedback, FeedbackConfig)
        assert isinstance(cfg.risk_ranking, RiskRankingConfig)
        assert isinstance(cfg.fp_tracking, FPTrackingConfig)
        assert isinstance(cfg.threshold_tuning, ThresholdTuningConfig)
        assert isinstance(cfg.active_exploitation, ActiveExploitationConfig)
        assert isinstance(cfg.safety, SafetyConfig)
        assert isinstance(cfg.retention, RetentionConfig)

    def test_db_path_property(self):
        cfg = LearningConfig()
        assert cfg.db_path == Path(".pipeline/telemetry.db")

    def test_db_path_custom(self):
        cfg = LearningConfig(database_path="/custom/path.db")
        assert cfg.db_path == Path("/custom/path.db")

    def test_from_dict_empty(self):
        cfg = LearningConfig.from_dict({})
        assert cfg.enabled is True
        assert cfg.database_path == ".pipeline/telemetry.db"

    def test_from_dict_top_level(self):
        cfg = LearningConfig.from_dict(
            {
                "enabled": False,
                "database_path": "/tmp/test.db",
                "update_mode": "online",
                "batch_retrain_interval": 100,
            }
        )
        assert cfg.enabled is False
        assert cfg.database_path == "/tmp/test.db"
        assert cfg.update_mode == "online"
        assert cfg.batch_retrain_interval == 100

    def test_from_dict_feedback(self):
        cfg = LearningConfig.from_dict(
            {
                "feedback": {
                    "decay_rate": 0.02,
                    "lookback_runs": 20,
                    "max_adaptation_weight": 3.0,
                }
            }
        )
        assert cfg.feedback.decay_rate == 0.02
        assert cfg.feedback.lookback_runs == 20
        assert cfg.feedback.max_adaptation_weight == 3.0

    def test_from_dict_feedback_partial(self):
        cfg = LearningConfig.from_dict({"feedback": {"decay_rate": 0.03}})
        assert cfg.feedback.decay_rate == 0.03
        assert cfg.feedback.lookback_runs == 10

    def test_from_dict_risk_ranking(self):
        cfg = LearningConfig.from_dict(
            {
                "risk_ranking": {
                    "exploration_parameter": 1.0,
                    "min_prior_probability": 0.01,
                    "blend_factor_initial": 0.1,
                    "blend_factor_growth_rate": 0.1,
                }
            }
        )
        assert cfg.risk_ranking.exploration_parameter == 1.0
        assert cfg.risk_ranking.min_prior_probability == 0.01
        assert cfg.risk_ranking.blend_factor_initial == 0.1
        assert cfg.risk_ranking.blend_factor_growth_rate == 0.1

    def test_from_dict_risk_ranking_partial(self):
        cfg = LearningConfig.from_dict({"risk_ranking": {"exploration_parameter": 0.8}})
        assert cfg.risk_ranking.exploration_parameter == 0.8
        assert cfg.risk_ranking.min_prior_probability == 0.001

    def test_from_dict_fp_tracking(self):
        cfg = LearningConfig.from_dict(
            {
                "fp_tracking": {
                    "target_fp_rate": 0.20,
                    "fp_rate_tolerance": 0.10,
                    "learning_rate": 0.10,
                    "convergence_window": 20,
                    "min_pattern_occurrences": 5,
                }
            }
        )
        assert cfg.fp_tracking.target_fp_rate == 0.20
        assert cfg.fp_tracking.fp_rate_tolerance == 0.10
        assert cfg.fp_tracking.learning_rate == 0.10
        assert cfg.fp_tracking.convergence_window == 20
        assert cfg.fp_tracking.min_pattern_occurrences == 5

    def test_from_dict_fp_tracking_partial(self):
        cfg = LearningConfig.from_dict({"fp_tracking": {"target_fp_rate": 0.25}})
        assert cfg.fp_tracking.target_fp_rate == 0.25
        assert cfg.fp_tracking.convergence_window == 10

    def test_from_dict_threshold_tuning(self):
        cfg = LearningConfig.from_dict(
            {
                "threshold_tuning": {
                    "learning_rate": 0.10,
                    "integral_gain": 0.01,
                    "max_adjustment_per_run": 0.10,
                    "min_threshold": 0.30,
                    "convergence_threshold": 0.02,
                }
            }
        )
        assert cfg.threshold_tuning.learning_rate == 0.10
        assert cfg.threshold_tuning.integral_gain == 0.01
        assert cfg.threshold_tuning.max_adjustment_per_run == 0.10
        assert cfg.threshold_tuning.min_threshold == 0.30
        assert cfg.threshold_tuning.convergence_threshold == 0.02

    def test_from_dict_threshold_tuning_partial(self):
        cfg = LearningConfig.from_dict({"threshold_tuning": {"min_threshold": 0.25}})
        assert cfg.threshold_tuning.min_threshold == 0.25
        assert cfg.threshold_tuning.learning_rate == 0.05

    def test_from_dict_retention(self):
        cfg = LearningConfig.from_dict(
            {
                "retention": {
                    "findings_days": 365,
                    "feedback_days": 180,
                    "risk_scores_days": 90,
                    "graph_edges_days": 90,
                    "plugin_stats_days": 180,
                    "performance_metrics_days": 365,
                    "session_state_days": 15,
                    "attack_chain_days": 180,
                }
            }
        )
        assert cfg.retention.findings_days == 365
        assert cfg.retention.feedback_days == 180
        assert cfg.retention.risk_scores_days == 90
        assert cfg.retention.graph_edges_days == 90
        assert cfg.retention.plugin_stats_days == 180
        assert cfg.retention.performance_metrics_days == 365
        assert cfg.retention.session_state_days == 15
        assert cfg.retention.attack_chain_days == 180

    def test_from_dict_retention_partial(self):
        cfg = LearningConfig.from_dict({"retention": {"findings_days": 100}})
        assert cfg.retention.findings_days == 100
        assert cfg.retention.feedback_days == 365

    def test_from_dict_ignores_invalid_subconfig_types(self):
        cfg = LearningConfig.from_dict({"feedback": "not_a_dict"})
        assert cfg.feedback.decay_rate == 0.01

        cfg = LearningConfig.from_dict({"risk_ranking": 123})
        assert cfg.risk_ranking.exploration_parameter == 0.5

        cfg = LearningConfig.from_dict({"fp_tracking": []})
        assert cfg.fp_tracking.target_fp_rate == 0.15

        cfg = LearningConfig.from_dict({"threshold_tuning": None})
        assert cfg.threshold_tuning.learning_rate == 0.05

        cfg = LearningConfig.from_dict({"retention": "invalid"})
        assert cfg.retention.findings_days == 730

    def test_from_dict_full_config(self):
        full = {
            "enabled": True,
            "database_path": "/data/telemetry.db",
            "update_mode": "batch",
            "batch_retrain_interval": 75,
            "feedback": {"decay_rate": 0.02, "lookback_runs": 15},
            "risk_ranking": {"exploration_parameter": 0.7},
            "fp_tracking": {"target_fp_rate": 0.10},
            "threshold_tuning": {"learning_rate": 0.08},
            "retention": {"findings_days": 400},
        }
        cfg = LearningConfig.from_dict(full)
        assert cfg.enabled is True
        assert cfg.database_path == "/data/telemetry.db"
        assert cfg.update_mode == "batch"
        assert cfg.batch_retrain_interval == 75
        assert cfg.feedback.decay_rate == 0.02
        assert cfg.feedback.lookback_runs == 15
        assert cfg.risk_ranking.exploration_parameter == 0.7
        assert cfg.fp_tracking.target_fp_rate == 0.10
        assert cfg.threshold_tuning.learning_rate == 0.08
        assert cfg.retention.findings_days == 400
