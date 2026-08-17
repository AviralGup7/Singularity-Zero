"""Regression: chain risk must use a real geometric mean of confidences."""

from __future__ import annotations

import json

import pytest

from src.learning.models.chain_result import ChainValidation


@pytest.mark.unit
def test_risk_score_uses_all_confidences() -> None:
    chain = ChainValidation(
        chain_pattern="ssrf_to_rce",
        description="ssrf then rce",
        findings=[
            {"id": "a", "severity": "high", "confidence": 0.81},
            {"id": "b", "severity": "medium", "confidence": 0.25},
        ],
        confidence=0.7,
        validation_action="validate",
    )
    expected_geom = (0.81 * 0.25) ** 0.5
    expected = round(7.5 * expected_geom * 1.2, 4)
    assert chain._compute_risk_score() == expected
    # Old code used only the first confidence: 0.81 ** 0.5
    old = round(7.5 * (0.81**0.5) * 1.2, 4)
    assert chain._compute_risk_score() != old


@pytest.mark.unit
def test_empty_findings_and_db_row() -> None:
    chain = ChainValidation(
        chain_pattern="x",
        description="y",
        findings=[],
        confidence=0.4,
        validation_action="skip",
    )
    assert chain._compute_risk_score() == 0.5
    row = chain.to_db_row("cid-1")
    assert row["chain_id"] == "cid-1"
    assert json.loads(row["finding_ids"]) == []
    assert row["risk_score"] == 0.5
