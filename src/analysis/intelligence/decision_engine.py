"""Model-backed classification and reportability decisions for findings.

Re-exports from :mod:`src.decision.prioritization.engine` to satisfy
decoupled architecture boundaries.
"""

from __future__ import annotations

from src.decision.prioritization.engine import (
    FINDING_HIGH_THRESHOLD,
    FINDING_LOW_THRESHOLD,
    FINDING_MEDIUM_THRESHOLD,
    FP_SUPPRESSION_PATTERNS,
    _diff_score,
    _get_dynamic_thresholds,
    _is_likely_false_positive,
    annotate_finding_decisions,
    classify_finding,
    filter_reportable_findings,
)

__all__ = [
    "FINDING_HIGH_THRESHOLD",
    "FINDING_LOW_THRESHOLD",
    "FINDING_MEDIUM_THRESHOLD",
    "FP_SUPPRESSION_PATTERNS",
    "_diff_score",
    "_get_dynamic_thresholds",
    "_is_likely_false_positive",
    "annotate_finding_decisions",
    "classify_finding",
    "filter_reportable_findings",
]


