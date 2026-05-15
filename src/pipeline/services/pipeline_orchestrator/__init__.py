"""Pipeline orchestrator for executing the security testing pipeline.

Coordinates all pipeline stages from subdomain enumeration through
report generation, with iterative analysis and feedback loops.

This package modularizes the pipeline orchestrator into separate files
for better maintainability and AI-agent editability.
"""

from ..pipeline_helpers import (
    extract_feedback_urls,
    finding_identity,
)
from ._constants import DEFAULT_ITERATION_LIMIT, PIPELINE_STAGES, STAGE_ORDER
from .learning_hooks import (
    apply_learning_adaptations,
    emit_feedback_events,
    run_learning_update,
)
from .orchestrator import FindingDict, PipelineOrchestrator
from .stages.analysis import run_passive_scanning
from .stages.enrichment import run_post_analysis_enrichments
from .stages.nuclei import run_nuclei_stage
from .stages.recon import (
    run_live_hosts,
    run_parameter_extraction,
    run_priority_ranking,
    run_subdomain_enumeration,
    run_url_collection,
)
from .stages.reporting import run_reporting
from .stages.semgrep import run_semgrep_stage

__all__ = [
    "PipelineOrchestrator",
    "PIPELINE_STAGES",
    "STAGE_ORDER",
    "DEFAULT_ITERATION_LIMIT",
    "FindingDict",
    "finding_identity",
    "extract_feedback_urls",
    "run_subdomain_enumeration",
    "run_live_hosts",
    "run_url_collection",
    "run_parameter_extraction",
    "run_priority_ranking",
    "run_passive_scanning",
    "run_post_analysis_enrichments",
    "run_nuclei_stage",
    "run_semgrep_stage",
    "run_reporting",
    "apply_learning_adaptations",
    "emit_feedback_events",
    "run_learning_update",
]
