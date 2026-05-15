"""Nuclei scanning stage."""

import asyncio
import time
from typing import Any

from src.analysis.intelligence.aggregator import (
    annotate_finding_decisions,
    annotate_finding_history,
    filter_reportable_findings,
    merge_findings,
)
from src.core.contracts.finding_lifecycle import apply_lifecycle
from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress
from src.pipeline.services.pipeline_helpers import (
    build_feedback_targets,
    build_stage_input_from_context,
)
from src.pipeline.storage import read_lines
from src.recon import build_nuclei_plan

logger = get_pipeline_logger(__name__)


async def run_nuclei_stage(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any = None,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Run nuclei scanning with JSONL output and merge findings into pipeline."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("nuclei", config, ctx)

    stage_started = time.monotonic()

    try:
        adaptive_tags = config.nuclei.get("adaptive_tags", {})
        previous_priority_urls: set[str] = (
            set(read_lines(ctx.previous_run / "priority_endpoints.txt"))
            if ctx.previous_run
            else set()
        )
        dedupe_nuclei = config.nuclei.get("dedupe_history", True)
        feedback_targets = build_feedback_targets(
            ctx.analysis_results,
            limit=int(config.nuclei.get("feedback_target_limit", 40)),
        )
        planned_nuclei_targets = [
            *ctx.priority_urls,
            *feedback_targets,
        ]
        deduped_from_history = (
            len({url for url in planned_nuclei_targets if url in previous_priority_urls})
            if dedupe_nuclei
            else 0
        )
        nuclei_targets = (
            [url for url in planned_nuclei_targets if url not in previous_priority_urls]
            if dedupe_nuclei
            else planned_nuclei_targets
        )
        if not nuclei_targets:
            ctx.mark_stage_skipped("nuclei", reason="no_new_targets_after_dedup")
            duration = round(time.monotonic() - stage_started, 2)
            return StageOutput(
                stage_name="nuclei",
                outcome=StageOutcome.SKIPPED,
                duration_seconds=duration,
                metrics={
                    "status": "skipped",
                    "reason": "no_new_targets_after_dedup",
                    "deduped_from_history": deduped_from_history,
                },
                state_delta={},
            )

        nuclei_plan = build_nuclei_plan(nuclei_targets, config, adaptive_tags)
        if not nuclei_plan:
            ctx.mark_stage_skipped("nuclei", reason="no_templates_matched")
            duration = round(time.monotonic() - stage_started, 2)
            return StageOutput(
                stage_name="nuclei",
                outcome=StageOutcome.SKIPPED,
                duration_seconds=duration,
                metrics={
                    "status": "skipped",
                    "reason": "no_templates_matched",
                    "deduped_from_history": deduped_from_history,
                },
                state_delta={},
            )

        emit_progress(
            "nuclei",
            f"Running nuclei with {len(nuclei_plan)} template groups",
            90,
        )
        nuclei_started = time.monotonic()

        from src.recon.nuclei import run_nuclei_with_parsing

        scope_hosts = {
            entry.strip().lower()
            for entry in ctx.scope_entries
            if entry.strip() and "*" not in entry
        }

        nuclei_output_file = str(ctx.output_store.run_dir / "nuclei.jsonl")
        parsed_findings = await asyncio.to_thread(
            run_nuclei_with_parsing,
            nuclei_targets,
            config,
            None,
            scope_hosts,
            nuclei_output_file,
        )

        nuclei_duration = round(time.monotonic() - nuclei_started, 2)

        state_delta: dict[str, Any] = {
            "nuclei_findings": parsed_findings,
            "analysis_results": dict(ctx.analysis_results),
            "merged_findings": list(ctx.merged_findings),
            "reportable_findings": list(ctx.reportable_findings),
        }

        if parsed_findings:
            state_delta["analysis_results"]["nuclei"] = parsed_findings
            merged = annotate_finding_decisions(
                annotate_finding_history(
                    ctx.previous_run,
                    merge_findings(
                        state_delta["analysis_results"],
                        ctx.selected_priority_items,
                        ctx.target_profile,
                        config.mode,
                        validation_summary=ctx.validation_summary,
                        nuclei_findings=parsed_findings,
                    ),
                )
            )
            state_delta["merged_findings"] = apply_lifecycle(merged)
            state_delta["reportable_findings"] = filter_reportable_findings(
                state_delta["merged_findings"]
            )

        ctx.mark_stage_complete("nuclei")
        emit_progress(
            "nuclei", f"Found {len(parsed_findings)} nuclei findings", 93, stage_percent=100
        )

        return StageOutput(
            stage_name="nuclei",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=nuclei_duration,
            metrics={
                "status": "ok",
                "duration_seconds": nuclei_duration,
                "template_groups": len(nuclei_plan),
                "targets_count": len(nuclei_targets),
                "deduped_from_history": deduped_from_history,
                "findings_count": len(parsed_findings),
            },
            state_delta=state_delta,
        )

    except Exception as exc:
        logger.error("Stage 'nuclei' failed: %s", exc)
        ctx.mark_stage_failed("nuclei", str(exc))
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="nuclei",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=str(exc),
            metrics={"status": "error", "error": str(exc)},
            state_delta={},
        )
