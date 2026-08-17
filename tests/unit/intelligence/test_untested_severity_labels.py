"""Coverage for public severity label mapping helpers."""

from __future__ import annotations

import pytest

from src.intelligence.severity_model import (
    SEVERITY_LABELS,
    SEVERITY_TO_IMPACT,
    SeverityPrediction,
    score_from_severity,
    severity_from_score,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("score", "label"),
    [
        (10.0, "critical"),
        (8.8, "critical"),
        (7.0, "high"),
        (6.8, "high"),
        (4.0, "medium"),
        (3.8, "medium"),
        (1.5, "low"),
        (0.4, "info"),
        (0.0, "info"),
        (-1.0, "info"),
    ],
)
def test_severity_from_score(score: float, label: str) -> None:
    assert severity_from_score(score) == label


@pytest.mark.unit
@pytest.mark.parametrize("label", SEVERITY_LABELS)
def test_score_from_severity_round_trip_order(label: str) -> None:
    numeric = score_from_severity(label)
    assert 0.0 <= numeric <= 10.0
    assert numeric == pytest.approx(SEVERITY_TO_IMPACT[label] * 10.0)


@pytest.mark.unit
def test_score_from_severity_unknown_uses_fallback() -> None:
    assert score_from_severity("nope") == pytest.approx(3.5)
    assert score_from_severity(None) == pytest.approx(3.5)
    assert score_from_severity(" HIGH ") == score_from_severity("high")


@pytest.mark.unit
def test_severity_prediction_metadata() -> None:
    pred = SeverityPrediction(
        score=7.2,
        severity="high",
        true_positive_probability=0.8,
        false_positive_probability=0.2,
        confidence=0.6,
        model_version="t",
        training_samples=3,
        calibration={"support": 0.1},
        top_features=["confidence"],
    )
    meta = pred.as_metadata()
    assert meta["model_version"] == "t"
    assert meta["training_samples"] == 3
    assert meta["top_features"] == ["confidence"]
    assert meta["true_positive_probability"] == 0.8
