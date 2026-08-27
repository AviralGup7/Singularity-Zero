"""Analysis Finding Intelligence & Scoring Package.

Provides finding decision classification, CVSS score mapping, attack surface insights,
and finding merger orchestration for the analysis subsystem.
"""

from __future__ import annotations

from typing import Any

from src.analysis.intelligence.decision_engine import (
    annotate_finding_decisions,
    classify_finding,
    filter_reportable_findings,
)

__all__ = [
    "attach_queue_replay_links",
    "build_technology_summary",
    "CVSSScore",
    "enrich_findings_with_cvss",
    "score_finding_cvss",
    "classify_finding",
    "annotate_finding_decisions",
    "filter_reportable_findings",
    "enrich_finding_with_model_severity",
    "enrich_findings_with_model_severity",
    "build_attack_surface",
    "build_cross_finding_correlation",
    "build_feedback_targets",
    "build_high_confidence_shortlist",
    "build_manual_verification_queue",
    "build_next_steps",
    "build_trend",
]


def __getattr__(name: str) -> Any:
    if name in {"attach_queue_replay_links", "build_technology_summary"}:
        from src.analysis.intelligence import aggregator

        return getattr(aggregator, name)
    if name in {"CVSSScore", "enrich_findings_with_cvss", "score_finding_cvss"}:
        from src.analysis.intelligence import cvss_scoring

        return getattr(cvss_scoring, name)
    if name in {
        "build_attack_surface",
        "build_cross_finding_correlation",
        "build_feedback_targets",
        "build_high_confidence_shortlist",
        "build_manual_verification_queue",
        "build_next_steps",
        "build_trend",
    }:
        from src.analysis.intelligence import insights

        return getattr(insights, name)
    if name in {"enrich_finding_with_model_severity", "enrich_findings_with_model_severity"}:
        from src.intelligence import severity_model

        return getattr(severity_model, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
