from src.analysis.automation.manual_queue import attach_queue_replay_links
from src.analysis.intelligence.decision_engine import (
    annotate_finding_decisions,
    filter_reportable_findings,
)
from src.analysis.intelligence.findings.intelligence_findings import (
    annotate_finding_history,
    merge_findings,
)
from src.analysis.intelligence.insights import (
    build_attack_surface,
    build_cross_finding_correlation,
    build_feedback_targets,
    build_high_confidence_shortlist,
    build_manual_verification_queue,
    build_next_steps,
    build_technology_summary,
    build_trend,
)
from src.core.plugins import register_plugin

ENRICHMENT_PROVIDER = "enrichment_provider"

# Wrap functions to register them
build_attack_surface = register_plugin(ENRICHMENT_PROVIDER, "attack_surface")(build_attack_surface)
build_trend = register_plugin(ENRICHMENT_PROVIDER, "trend")(build_trend)
build_technology_summary = register_plugin(ENRICHMENT_PROVIDER, "technology_summary")(
    build_technology_summary
)
build_next_steps = register_plugin(ENRICHMENT_PROVIDER, "next_steps")(build_next_steps)
build_manual_verification_queue = register_plugin(ENRICHMENT_PROVIDER, "manual_verification_queue")(
    build_manual_verification_queue
)
build_high_confidence_shortlist = register_plugin(ENRICHMENT_PROVIDER, "high_confidence_shortlist")(
    build_high_confidence_shortlist
)
build_cross_finding_correlation = register_plugin(ENRICHMENT_PROVIDER, "cross_finding_correlation")(
    build_cross_finding_correlation
)

__all__ = [
    "merge_findings",
    "build_attack_surface",
    "build_trend",
    "annotate_finding_history",
    "build_technology_summary",
    "build_next_steps",
    "build_feedback_targets",
    "build_manual_verification_queue",
    "attach_queue_replay_links",
    "build_high_confidence_shortlist",
    "annotate_finding_decisions",
    "filter_reportable_findings",
    "build_cross_finding_correlation",
]
