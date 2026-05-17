"""Intelligence correlation module for merging and analyzing findings.

Re-exports finding merge, history annotation, and insight-building functions
from the analysis layer for use by the intelligence package.
Also provides cross-finding correlation for attack chain detection and compound risk scoring.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.analysis.intelligence.findings.intelligence_findings import (
    annotate_finding_history,
    merge_findings,
)
from src.analysis.intelligence.insights import (
    build_attack_surface,
    build_feedback_targets,
    build_high_confidence_shortlist,
    build_manual_verification_queue,
    build_next_steps,
    build_technology_summary,
    build_trend,
)
from src.intelligence.correlation.engine import (
    ATTACK_CHAINS,
    calculate_compound_risk,
    correlate_findings,
    detect_multi_vector_endpoints,
)

__all__ = [
    "annotate_finding_history",
    "build_attack_surface",
    "build_feedback_targets",
    "build_high_confidence_shortlist",
    "build_manual_verification_queue",
    "merge_findings",
    "build_next_steps",
    "build_technology_summary",
    "build_trend",
    "correlate_findings",
    "detect_multi_vector_endpoints",
    "calculate_compound_risk",
    "ATTACK_CHAINS",
]
