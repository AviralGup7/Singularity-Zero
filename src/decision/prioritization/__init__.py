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


from src.decision.prioritization.engine import (
    _diff_score,
    _get_dynamic_thresholds,
    _is_likely_false_positive,
    annotate_finding_decisions as _engine_annotate,
    classify_finding as _engine_classify,
    filter_reportable_findings as _engine_filter,
)


def _default_classify_finding(
    finding: dict[str, Any], target_profile: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Model-backed classification fallback when no external handler is registered."""
    return _engine_classify(finding, target_profile)


def _default_annotate_finding_decisions(
    findings: list[dict[str, Any]], target_profile: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Model-backed annotation fallback when no external handler is registered."""
    return _engine_annotate(findings, target_profile)


def _default_filter_reportable_findings(
    findings: list[dict[str, Any]], target_profile: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Model-backed filtering fallback when no external handler is registered."""
    return _engine_filter(findings)


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
