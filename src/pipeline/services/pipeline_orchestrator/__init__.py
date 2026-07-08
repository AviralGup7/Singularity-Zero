"""Pipeline orchestrator for executing the security testing pipeline.

Coordinates all pipeline stages from subdomain enumeration through
report generation, with iterative analysis and feedback loops.

This package modularizes the pipeline orchestrator into separate files
for better maintainability and AI-agent editability.
"""

import importlib
from typing import Any

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

# Lazy imports for stage runners to avoid eagerly pulling in all stage
# dependencies (reporting, validators, etc.) at package import time.
_LAZY_STAGE_IMPORTS: dict[str, tuple[str, str]] = {
    "run_passive_scanning": (".stages.analysis", "run_passive_scanning"),
    "run_post_analysis_enrichments": (".stages.enrichment", "run_post_analysis_enrichments"),
    "run_nuclei_stage": (".stages.nuclei", "run_nuclei_stage"),
    "run_subdomain_enumeration": (".stages.recon", "run_subdomain_enumeration"),
    "run_live_hosts": (".stages.recon", "run_live_hosts"),
    "run_url_collection": (".stages.recon", "run_url_collection"),
    "run_parameter_extraction": (".stages.recon", "run_parameter_extraction"),
    "run_priority_ranking": (".stages.recon", "run_priority_ranking"),
    "run_reporting": (".stages.reporting", "run_reporting"),
    "run_semgrep_stage": (".stages.semgrep", "run_semgrep_stage"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_STAGE_IMPORTS:
        module_path, attr_name = _LAZY_STAGE_IMPORTS[name]
        module = importlib.import_module(module_path, package=__name__)
        value = getattr(module, attr_name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
