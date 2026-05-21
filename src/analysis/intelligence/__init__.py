"""Intelligence package exports."""

from src.analysis.intelligence.aggregator import (
    attach_queue_replay_links,
    build_technology_summary,
)
from src.analysis.intelligence.cvss_scoring import (
    CVSSScore,
    enrich_findings_with_cvss,
    score_finding_cvss,
)
from src.analysis.intelligence.decision_engine import (
    annotate_finding_decisions,
    classify_finding,
    filter_reportable_findings,
)
from src.analysis.intelligence.insights import (
    build_attack_surface,
    build_cross_finding_correlation,
    build_feedback_targets,
    build_high_confidence_shortlist,
    build_manual_verification_queue,
    build_next_steps,
    build_trend,
)
from src.intelligence.severity_model import (
    enrich_finding_with_model_severity,
    enrich_findings_with_model_severity,
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
