from __future__ import annotations

from src.detection.coverage_map import coverage_report
from src.detection.scoring import rank, score_finding
from src.detection.taxonomy import classify_key, families


def test_score_blends_evidence_and_fp() -> None:
    high = score_finding(
        severity="high", plugin_confidence=0.6, evidence_points=3, corroborated=True
    )
    fp = score_finding(severity="high", plugin_confidence=0.6, false_positive_hits=2)
    assert high.confidence > fp.confidence
    ordered = rank([fp, high])
    assert ordered[0] is high


def test_taxonomy_and_coverage() -> None:
    taxon = classify_key("graphql_introspection")
    assert taxon.family == "api"
    report = coverage_report()
    assert report["total"] >= 80
    assert families()


def test_sqli_family() -> None:
    assert classify_key("sqli_safe_probe").family == "injection"
