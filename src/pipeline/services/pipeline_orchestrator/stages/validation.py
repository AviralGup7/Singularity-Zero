"""Validation stage — extracts validation runtime from analysis.py into standalone stage."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.pipeline_logging import instrument
from src.pipeline.runner_support import emit_progress

logger = get_pipeline_logger(__name__)


@instrument("validation")
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

    validation_summary: dict[str, Any] = {
        "results": {},
        "errors": [],
        "settings": {},
        "metric": {},
        "metrics": {},
    }
    validation_ok = False

    import uuid

    from src.core.frontier.authority_runtime import get_current_hunt_budget
    from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer
    from src.decision.models import (
        ActionSpec,
        ExecutionRequest,
        ResourceLimits,
        ScopeToken,
        TargetSpec,
    )
    from src.execution.request_executor import ExecutionRequestWorker

    enforcer = (
        getattr(ctx, "budget_enforcer", None)
        or get_current_hunt_budget()
        or HuntBudgetEnforcer(HuntBudget(max_requests=200), label="validation")
    )
    from src.pipeline.authority_bootstrap import resolve_execution_authorizer

    authorizer = resolve_execution_authorizer(ctx=ctx, budget_enforcer=enforcer)
    worker = ExecutionRequestWorker(authorizer=authorizer)
    stage_ticket = getattr(ctx, "execution_ticket", None)

    for attempt in range(1, 3):
        try:
            from src.core.contracts.protocol_registry import get_validation_runtime

            _validation_runtime = get_validation_runtime()
            if _validation_runtime is None:
                raise RuntimeError("Validation runtime not registered")

            action = ActionSpec(
                action_id=f"act_val_{uuid.uuid4().hex[:8]}",
                action_type="validation_run",
                tool_or_detector="validation_runtime",
                payload=(("attempt", attempt),),
            )

            req = ExecutionRequest(
                request_id=f"req_val_{uuid.uuid4().hex[:12]}",
                tenant_id=str(getattr(ctx, "tenant_id", "default") or "default"),
                target=TargetSpec(host="localhost", path="/validation"),
                stage="validation",
                actions=(action,),
                resource_limits=ResourceLimits(timeout_seconds=300.0),
                scope_token=ScopeToken(scope_hash="val_scope", allowed_domains=("localhost",)),
                deadline=time.time() + 360.0,
            )

            def _run_val_action(act: ActionSpec, r: ExecutionRequest) -> dict[str, Any]:
                summary = _validation_runtime(
                    analysis_results,
                    ranked_priority_urls,
                    config.extensions,
                    config.mode,
                    validation_runtime_inputs,
                )
                return {"summary": summary}

            worker.register_handler("validation_run", _run_val_action)

            def _execute_worker() -> dict[str, Any]:
                # F-004: stage admit already reserved+consumed.
                if stage_ticket is not None:
                    action_res = _run_val_action(action, req)
                    summary = action_res.get("summary", {})
                    return summary if isinstance(summary, dict) else {}
                ticket = authorizer.authorize(req)
                res = worker.execute(ticket)
                if res.outcome == "REJECTED":
                    raise RuntimeError(f"Validation execution rejected: {res.error}")
                artifacts = dict(res.artifacts)
                action_res = artifacts.get(f"action_{action.action_id}", {})
                summary = action_res.get("summary", {})
                return summary if isinstance(summary, dict) else {}

            validation_summary = await asyncio.to_thread(_execute_worker)
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
