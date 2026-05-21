"""Golden-set tests for the learning-backed signal-quality filter."""

from pathlib import Path

from src.learning.signal_quality import evaluate_golden_set, score_signal_quality


FIXTURE = Path("tests/fixtures/golden_false_positive_findings.json")


def test_signal_quality_suppresses_known_fp_pattern() -> None:
    result = score_signal_quality(
        {
            "category": "anomaly",
            "confidence": 0.68,
            "true_positive_probability": 0.24,
            "false_positive_probability": 0.76,
            "evidence": {
                "body_snippet": "too many requests, rate limit exceeded",
                "diff": {"mutated_status": 429, "content_changed": True},
            },
        }
    )

    assert result.reportable is False
    assert result.action == "suppress"
    assert result.false_positive_probability > result.true_positive_probability


def test_signal_quality_keeps_reproducible_validated_signal() -> None:
    result = score_signal_quality(
        {
            "category": "idor",
            "confidence": 0.76,
            "true_positive_probability": 0.70,
            "false_positive_probability": 0.30,
            "combined_signal": "auth + idor",
            "evidence": {
                "reproducible": True,
                "diff": {"status_changed": True, "content_changed": True, "body_similarity": 0.25},
            },
        }
    )

    assert result.reportable is True
    assert result.true_positive_probability > 0.70


def test_golden_set_reduces_false_positives_by_half() -> None:
    result = evaluate_golden_set(FIXTURE)

    assert result.passed is True
    assert result.fp_reduction >= 0.50
    assert result.true_positive_retention >= 0.90
    assert result.filtered_fp_per_1000_real <= result.baseline_fp_per_1000_real / 2
