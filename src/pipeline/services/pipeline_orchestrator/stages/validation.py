"""Validation stage — extracts validation runtime from analysis.py into standalone stage."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.execution.validators import execute_validation_runtime
from src.pipeline.runner_support import emit_progress

logger = get_pipeline_logger(__name__)


async def run_validation(
    args: Any,
    config: Any,
    ctx: PipelineContext,
) -> StageOutput:
    """Stage: Run validation runtime against analysis results.

    Extracted from inline validation in analysis.py to be a standalone stage
    with its own checkpoint, timeout, retry, and metrics.
    """
    stage_started = time.monotonic()
    analysis_results = getattr(ctx.result, "analysis_results", {}) or {}
    ranked_priority_urls = getattr(ctx.result, "ranked_priority_urls", []) or []
    validation_runtime_inputs = getattr(ctx.result, "validation_runtime_inputs", {}) or {}

    state_delta: dict[str, Any] = {
        "validation_summary": {
            "results": {},
            "errors": [],
            "settings": {},
            "metric": {},
            "metrics": {},
        },
        "validation_ok": False,
    }

    if not analysis_results:
        logger.info("Validation: no analysis results available, skipping")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="validation",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={
                "status": "skipped",
                "reason": "no_analysis_results",
                "duration_seconds": duration,
            },
            state_delta=state_delta,
        )

    emit_progress("validation", "Running validation checks", 92)

    from typing import Any
    validation_summary: dict[str, Any] = {
        "results": {},
        "errors": [],
        "settings": {},
        "metric": {},
        "metrics": {},
    }
    validation_ok = False

    for attempt in range(1, 3):
        try:
            validation_summary = await asyncio.to_thread(
                execute_validation_runtime,
                analysis_results,
                ranked_priority_urls,
                config.extensions,
                config.mode,
                validation_runtime_inputs,
            )
            validation_ok = True
            break
        except Exception as exc:
            logger.warning(
                "Validation attempt %d failed: %s",
                attempt,
                exc,
            )
            if attempt == 2:
                logger.error(
                    "Validation failed after 2 retries, continuing with empty summary",
                )
                validation_summary = {
                    "results": {},
                    "errors": [f"Validation runtime failed: {exc}"],
                    "settings": {},
                    "metric": {},
                    "metrics": {},
                }

    state_delta["validation_summary"] = validation_summary
    state_delta["validation_ok"] = validation_ok

    duration = round(time.monotonic() - stage_started, 2)
    emit_progress(
        "validation",
        f"Validation complete: {'passed' if validation_ok else 'failed'}",
        94,
    )
    logger.info(
        "Validation completed: %s (%.1fs)",
        "passed" if validation_ok else "failed",
        duration,
    )

    return StageOutput(
        stage_name="validation",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=duration,
        metrics={
            "status": "ok" if validation_ok else "warning",
            "duration_seconds": duration,
            "validation_ok": validation_ok,
            "errors_count": len(validation_summary.get("errors", [])),
        },
        state_delta=state_delta,
    )
