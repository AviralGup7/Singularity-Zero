"""Coverage for active-probe confidence/severity helpers."""

from __future__ import annotations

import pytest

from src.analysis.helpers._probe_utils import (
    probe_confidence,
    probe_confidence_from_map,
    probe_severity,
    probe_severity_from_map,
)


@pytest.mark.unit
def test_probe_confidence_uses_map_and_caps() -> None:
    assert probe_confidence(["a"]) == 0.5
    cmap = {"sqli": 0.8, "xss": 0.6}
    assert probe_confidence(["sqli", "xss"], confidence_map=cmap) == 0.84
    assert probe_confidence_from_map([], cmap) == 0.5
    assert probe_confidence_from_map(["sqli"] * 10, cmap, cap=0.83) == 0.83


@pytest.mark.unit
def test_probe_severity_picks_highest_known() -> None:
    smap = {"a": "low", "b": "high", "c": "medium"}
    assert probe_severity(["x"]) == "low"
    assert probe_severity(["a", "b", "c"], severity_map=smap) == "high"
    assert probe_severity_from_map([], smap) == "low"
    assert probe_severity_from_map(["missing"], smap) == "low"
