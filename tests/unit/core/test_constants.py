"""Unit tests for src.core.constants."""

import unittest

import pytest

from src.core import constants as C


@pytest.mark.unit
class TestPipelineLimits(unittest.TestCase):
    def test_max_iteration_limit_is_positive(self) -> None:
        self.assertGreater(C.MAX_ITERATION_LIMIT, 0)

    def test_feedback_url_limit_is_positive(self) -> None:
        self.assertGreater(C.FEEDBACK_URL_LIMIT, 0)

    def test_confidence_degradation_threshold_in_unit_range(self) -> None:
        self.assertGreaterEqual(C.CONFIDENCE_DEGRADATION_THRESHOLD, 0.0)
        self.assertLessEqual(C.CONFIDENCE_DEGRADATION_THRESHOLD, 1.0)

    def test_min_new_findings_for_continue_positive(self) -> None:
        self.assertGreaterEqual(C.MIN_NEW_FINDINGS_FOR_CONTINUE, 1)

    def test_convergence_iterations_positive(self) -> None:
        self.assertGreaterEqual(C.CONVERGENCE_ITERATIONS, 1)


@pytest.mark.unit
class TestSeverityScores(unittest.TestCase):
    def test_severity_scores_has_all_levels(self) -> None:
        for level in ("critical", "high", "medium", "low", "info"):
            self.assertIn(level, C.SEVERITY_SCORES)

    def test_severity_scores_descending(self) -> None:
        self.assertGreater(C.SEVERITY_SCORES["critical"], C.SEVERITY_SCORES["high"])
        self.assertGreater(C.SEVERITY_SCORES["high"], C.SEVERITY_SCORES["medium"])
        self.assertGreater(C.SEVERITY_SCORES["medium"], C.SEVERITY_SCORES["low"])
        self.assertGreater(C.SEVERITY_SCORES["low"], C.SEVERITY_SCORES["info"])

    def test_severity_priority_scores_descending(self) -> None:
        for a, b in (("critical", "high"), ("high", "medium"), ("medium", "low")):
            self.assertGreater(C.SEVERITY_PRIORITY_SCORES[a], C.SEVERITY_PRIORITY_SCORES[b])


@pytest.mark.unit
class TestAnalysisDefaults(unittest.TestCase):
    def test_default_analyzer_timeout_positive(self) -> None:
        self.assertGreater(C.DEFAULT_ANALYZER_TIMEOUT_SECONDS, 0)

    def test_default_analyzer_max_workers_positive(self) -> None:
        self.assertGreater(C.DEFAULT_ANALYZER_MAX_WORKERS, 0)

    def test_screenshot_defaults_positive(self) -> None:
        self.assertGreater(C.DEFAULT_SCREENSHOT_MAX_WORKERS, 0)
        self.assertGreater(C.DEFAULT_SCREENSHOT_MAX_HOSTS, 0)
        self.assertGreater(C.DEFAULT_SCREENSHOT_TIMEOUT_SECONDS, 0)
        self.assertIn(",", C.DEFAULT_SCREENSHOT_WINDOW_SIZE)


@pytest.mark.unit
class TestRetryConstants(unittest.TestCase):
    def test_retry_jitter_factor_in_unit_range(self) -> None:
        self.assertGreaterEqual(C.DEFAULT_RETRY_JITTER_FACTOR, 0.0)
        self.assertLessEqual(C.DEFAULT_RETRY_JITTER_FACTOR, 1.0)


@pytest.mark.unit
class TestAllowedOrigins(unittest.TestCase):
    def test_includes_localhost_origins(self) -> None:
        self.assertIn("http://localhost:5173", C.DEFAULT_ALLOWED_ORIGINS)
        self.assertIn("http://localhost:3000", C.DEFAULT_ALLOWED_ORIGINS)
        self.assertIn("http://127.0.0.1:5173", C.DEFAULT_ALLOWED_ORIGINS)
        self.assertIn("http://127.0.0.1:3000", C.DEFAULT_ALLOWED_ORIGINS)


@pytest.mark.unit
class TestScanQualityWeights(unittest.TestCase):
    def test_weights_sum_to_one(self) -> None:
        total = sum(C.SCAN_QUALITY_WEIGHTS.values())
        self.assertAlmostEqual(total, 1.0, places=6)

    def test_all_weights_in_unit_range(self) -> None:
        for weight in C.SCAN_QUALITY_WEIGHTS.values():
            self.assertGreaterEqual(weight, 0.0)
            self.assertLessEqual(weight, 1.0)

    def test_weights_keys(self) -> None:
        for key in (
            "module_coverage",
            "validation_coverage",
            "high_confidence_pct",
            "intelligence_coverage",
        ):
            self.assertIn(key, C.SCAN_QUALITY_WEIGHTS)


@pytest.mark.unit
class TestHealthScoreMultipliers(unittest.TestCase):
    def test_descending_severity_multipliers(self) -> None:
        self.assertGreater(
            C.HEALTH_SCORE_MULTIPLIERS["critical"], C.HEALTH_SCORE_MULTIPLIERS["high"]
        )
        self.assertGreater(
            C.HEALTH_SCORE_MULTIPLIERS["high"], C.HEALTH_SCORE_MULTIPLIERS["medium"]
        )

    def test_positive_multipliers(self) -> None:
        for value in C.HEALTH_SCORE_MULTIPLIERS.values():
            self.assertGreater(value, 0)


if __name__ == "__main__":
    unittest.main()
