"""Semgrep scanning stage."""

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
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

logger = get_pipeline_logger(__name__)


async def run_semgrep_stage(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any = None,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Parse Semgrep JSON output and merge findings into pipeline."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("semgrep", config, ctx)

    stage_started = time.monotonic()
    semgrep_output_file = ctx.output_store.run_dir / "semgrep.json"

    if not semgrep_output_file.exists():
        ctx.mark_stage_skipped("semgrep", reason="no_semgrep_output")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="semgrep",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={
                "status": "skipped",
                "reason": "no_semgrep_output",
            },
            state_delta={},
        )

    try:
        emit_progress("semgrep", "Parsing semgrep output", 90)

        from src.core.parsers.semgrep_parser import parse_semgrep_json_file

        parsed_findings = await asyncio.to_thread(parse_semgrep_json_file, str(semgrep_output_file))
        semgrep_duration = round(time.monotonic() - stage_started, 2)

        state_delta: dict[str, Any] = {
            "analysis_results": dict(ctx.analysis_results),
            "merged_findings": list(ctx.merged_findings),
            "reportable_findings": list(ctx.reportable_findings),
        }

        if parsed_findings:
            state_delta["analysis_results"]["semgrep"] = parsed_findings
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

        ctx.mark_stage_complete("semgrep")
        emit_progress(
            "semgrep",
            f"Found {len(parsed_findings)} semgrep findings",
            93,
            stage_percent=100,
        )

        return StageOutput(
            stage_name="semgrep",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=semgrep_duration,
            metrics={
                "status": "ok",
                "duration_seconds": semgrep_duration,
                "findings_count": len(parsed_findings),
            },
            state_delta=state_delta,
        )

    except Exception as exc:
        logger.error("Stage 'semgrep' failed: %s", exc)
        ctx.mark_stage_failed("semgrep", str(exc))
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="semgrep",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=str(exc),
            metrics={"status": "error", "error": str(exc)},
            state_delta={},
        )
