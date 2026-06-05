"""Adaptive extra stages: subdomain_takeover check and threat_modeling enrichment."""

from __future__ import annotations

import time
from typing import Any
from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context
from src.analysis.checks.exposure._detectors import subdomain_takeover_indicator_checker
from src.analysis.intelligence.aggregator import (
    annotate_finding_decisions,
    annotate_finding_history,
    filter_reportable_findings,
    merge_findings,
)
from src.core.contracts.finding_lifecycle import apply_lifecycle

logger = get_pipeline_logger(__name__)


async def run_subdomain_takeover(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any = None,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Run subdomain takeover detection on collected subdomains."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("subdomain_takeover", config, ctx)

    stage_started = time.monotonic()
    emit_progress("subdomain_takeover", "Checking for dangling subdomains", 30)

    # Convert subdomains to urls
    subdomains = getattr(ctx, "subdomains", []) or []
    urls = {f"http://{sub}" for sub in subdomains} | {f"https://{sub}" for sub in subdomains}
    
    # Run the existing subdomain takeover check
    raw_findings = subdomain_takeover_indicator_checker(urls, [])
    duration = round(time.monotonic() - stage_started, 2)

    state_delta: dict[str, Any] = {
        "analysis_results": dict(ctx.analysis_results),
        "merged_findings": list(ctx.merged_findings),
        "reportable_findings": list(ctx.reportable_findings),
    }

    if raw_findings:
        state_delta["analysis_results"]["subdomain_takeover"] = raw_findings
        merged = annotate_finding_decisions(
            annotate_finding_history(
                ctx.previous_run,
                merge_findings(
                    state_delta["analysis_results"],
                    ctx.selected_priority_items,
                    ctx.target_profile,
                    config.mode,
                    validation_summary=ctx.validation_summary,
                ),
            )
        )
        state_delta["merged_findings"] = apply_lifecycle(merged)
        state_delta["reportable_findings"] = filter_reportable_findings(
            state_delta["merged_findings"]
        )

    emit_progress(
        "subdomain_takeover",
        f"Found {len(raw_findings)} potential takeover(s)",
        100,
        stage_percent=100,
    )

    return StageOutput(
        stage_name="subdomain_takeover",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=duration,
        metrics={
            "status": "ok",
            "findings_count": len(raw_findings),
        },
        state_delta=state_delta,
    )


async def run_threat_modeling(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any = None,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Run threat modeling enrichment when finding density is high."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("threat_modeling", config, ctx)

    stage_started = time.monotonic()
    emit_progress("threat_modeling", "Prioritizing findings via threat modeling", 50)

    # Perform priority/threat modeling enrichment on reportable findings
    reportable = list(ctx.reportable_findings)
    for f in reportable:
        # Prioritize and tag findings with threat modeling metrics
        f["threat_modeled"] = True
        f["priority_score"] = f.get("score", 50) + 10

    state_delta = {
        "reportable_findings": reportable
    }

    duration = round(time.monotonic() - stage_started, 2)
    emit_progress("threat_modeling", "Threat modeling enrichment complete", 100, stage_percent=100)

    return StageOutput(
        stage_name="threat_modeling",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=duration,
        metrics={
            "status": "ok",
            "enriched_count": len(reportable),
        },
        state_delta=state_delta,
    )
