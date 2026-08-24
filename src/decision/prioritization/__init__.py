from __future__ import annotations

from collections.abc import Callable
from typing import Any

_annotate_finding_decisions_handler: Callable[..., Any] | None = None
_classify_finding_handler: Callable[..., Any] | None = None
_filter_reportable_findings_handler: Callable[..., Any] | None = None


def register_prioritization_handlers(
    annotate_handler: Callable[..., Any],
    classify_handler: Callable[..., Any],
    filter_handler: Callable[..., Any],
) -> None:
    """Register external prioritization handlers (e.g. from analysis intelligence)."""
    global \
        _annotate_finding_decisions_handler, \
        _classify_finding_handler, \
        _filter_reportable_findings_handler
    _annotate_finding_decisions_handler = annotate_handler
    _classify_finding_handler = classify_handler
    _filter_reportable_findings_handler = filter_handler


def _default_classify_finding(
    finding: dict[str, Any], target_profile: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Resilient classification fallback that attempts analysis binding lazily."""
    try:
        from src.analysis.intelligence.decision_engine import (
            classify_finding as ana_classify,
        )

        return ana_classify(finding, target_profile)
    except Exception:
        conf = float(finding.get("confidence", 0.5) or 0.5)
        decision = "HIGH" if conf >= 0.72 else ("MEDIUM" if conf >= 0.45 else "DROP")
        return {
            "decision": decision,
            "reason": f"Fallback classification based on confidence {conf:.2f}",
            "confidence_factors": {"base": conf},
            "diff_score": 0,
            "diff_classification": "",
            "suppress_reason": "",
            "thresholds_used": {"low": 0.45, "medium": 0.58, "high": 0.72},
            "reportable": decision != "DROP",
        }


def _default_annotate_finding_decisions(
    findings: list[dict[str, Any]], target_profile: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Resilient annotation fallback that attempts analysis binding lazily."""
    try:
        from src.analysis.intelligence.decision_engine import (
            annotate_finding_decisions as ana_annotate,
        )

        return ana_annotate(findings, target_profile)
    except Exception:
        annotated = []
        for f in findings:
            item = dict(f)
            dec = _default_classify_finding(item, target_profile)
            item["decision"] = dec["decision"]
            item["reportable"] = dec.get("reportable", dec["decision"] != "DROP")
            item["decision_reason"] = dec.get("reason", "")
            item["diff_score"] = dec.get("diff_score", 0)
            item["diff_classification"] = dec.get("diff_classification", "")
            item["suppress_reason"] = dec.get("suppress_reason", "")
            annotated.append(item)
        return annotated


def _default_filter_reportable_findings(
    findings: list[dict[str, Any]], target_profile: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Resilient filtering fallback that attempts analysis binding lazily."""
    try:
        from src.analysis.intelligence.decision_engine import (
            filter_reportable_findings as ana_filter,
        )

        return ana_filter(findings)
    except Exception:
        return [f for f in findings if str(f.get("decision", "MEDIUM")).upper() != "DROP"]


def annotate_finding_decisions(*args: Any, **kwargs: Any) -> Any:
    if _annotate_finding_decisions_handler is not None:
        return _annotate_finding_decisions_handler(*args, **kwargs)
    return _default_annotate_finding_decisions(*args, **kwargs)


def classify_finding(*args: Any, **kwargs: Any) -> Any:
    if _classify_finding_handler is not None:
        return _classify_finding_handler(*args, **kwargs)
    return _default_classify_finding(*args, **kwargs)


def filter_reportable_findings(*args: Any, **kwargs: Any) -> Any:
    if _filter_reportable_findings_handler is not None:
        return _filter_reportable_findings_handler(*args, **kwargs)
    return _default_filter_reportable_findings(*args, **kwargs)


__all__ = [
    "annotate_finding_decisions",
    "classify_finding",
    "filter_reportable_findings",
    "register_prioritization_handlers",
]
