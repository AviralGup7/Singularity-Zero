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
    global \
        _annotate_finding_decisions_handler, \
        _classify_finding_handler, \
        _filter_reportable_findings_handler
    _annotate_finding_decisions_handler = annotate_handler
    _classify_finding_handler = classify_handler
    _filter_reportable_findings_handler = filter_handler


def _ensure_prioritization_handlers() -> None:
    """Bind the analysis decision engine if plugin registration has not run."""
    if (
        _annotate_finding_decisions_handler is not None
        and _classify_finding_handler is not None
        and _filter_reportable_findings_handler is not None
    ):
        return
    from src.analysis.intelligence.decision_engine import (
        annotate_finding_decisions as ana_annotate,
    )
    from src.analysis.intelligence.decision_engine import (
        classify_finding as ana_classify,
    )
    from src.analysis.intelligence.decision_engine import (
        filter_reportable_findings as ana_filter,
    )

    register_prioritization_handlers(ana_annotate, ana_classify, ana_filter)


def annotate_finding_decisions(*args: Any, **kwargs: Any) -> Any:
    _ensure_prioritization_handlers()
    if _annotate_finding_decisions_handler is not None:
        return _annotate_finding_decisions_handler(*args, **kwargs)
    raise RuntimeError("No annotate_finding_decisions_handler registered in src.decision")


def classify_finding(*args: Any, **kwargs: Any) -> Any:
    _ensure_prioritization_handlers()
    if _classify_finding_handler is not None:
        return _classify_finding_handler(*args, **kwargs)
    raise RuntimeError("No classify_finding_handler registered in src.decision")


def filter_reportable_findings(*args: Any, **kwargs: Any) -> Any:
    _ensure_prioritization_handlers()
    if _filter_reportable_findings_handler is not None:
        return _filter_reportable_findings_handler(*args, **kwargs)
    raise RuntimeError("No filter_reportable_findings_handler registered in src.decision")


__all__ = ["annotate_finding_decisions", "classify_finding", "filter_reportable_findings"]
