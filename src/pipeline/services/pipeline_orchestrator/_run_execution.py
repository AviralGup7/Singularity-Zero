"""Neural-Mesh execution entry-point.

Drives the :class:`ActorScheduler` to execute the pipeline graph
with per-node readiness polling, conditional gating, and priority
ordering.  Replaces the legacy tier-batched runner that lived here
prior to the actor-scheduler refactor.

Concrete helpers live in the ``_orchestrator`` sub-package:

* Fatal failure detection → ``_orchestrator.fatal_detection``
* Recon output validation  → ``_orchestrator.recon_validator``
* Stage error collection   → ``_orchestrator.error_reporting``
* Stage retry execution    → ``_orchestrator.retry``
"""
from __future__ import annotations

import argparse
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext, StageStatus

from ._orchestrator import validate_recon_outputs
from .actor_scheduler import ActorScheduler
from .graph_builder import build_pipeline_graph

logger = get_pipeline_logger(__name__)


async def execute_remaining_stages(
    orchestrator: Any,
    *,
    remaining_stages: list[str],
    stage_methods: dict[str, Any],
    args: argparse.Namespace,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any,
    nuclei_available: bool,
    checkpoint_mgr: Any,
    handled_by_parallel: set[str],
    stage_checkpoint_guard: Any,
    progress_emitter: Any,
    error_emitter: Any,
) -> int | None:
    """Execute the pipeline using the ActorScheduler.

    ``handled_by_parallel`` is accepted for backward compatibility with
    callers that previously separated "tier stages" from "parallel
    stages".  In the actor model every stage is dispatched uniformly
    by the readiness loop, so the set is no longer populated by this
    function — callers can still inspect it for telemetry if they
    wish.
    """
    graph = build_pipeline_graph(stage_methods)
    logger.info(
        "Neural-Mesh ActorScheduler: greedy readiness loop "
        "(%d nodes, %d remaining, %d pre-completed)",
        len(graph.nodes),
        len(remaining_stages),
        len(checkpoint_mgr.completed_stages)
        if hasattr(checkpoint_mgr, "completed_stages")
        else 0,
    )

    completed_stages: set[str] = set()
    if hasattr(checkpoint_mgr, "completed_stages"):
        completed_stages.update(checkpoint_mgr.completed_stages)

    # The recon validator is a post-completion hook on ``urls``.  It
    # sets ``recon_validation=FAILED`` in the context when the URL
    # collection completed but produced no discoverable URLs.  The
    # exit-code resolver consults that flag to decide whether to
    # surface a non-zero exit for a dead-scope run.
    post_hooks: dict[str, Any] = {
        "urls": lambda _ctx: validate_recon_outputs(ctx),
    }

    scheduler = ActorScheduler(
        graph=graph,
        stage_methods=stage_methods,
        ctx=ctx,
        remaining_stages=list(remaining_stages),
        completed_stages=completed_stages,
        orchestrator=orchestrator,
        args=args,
        config=config,
        scope_interceptor=scope_interceptor,
        nuclei_available=nuclei_available,
        checkpoint_mgr=checkpoint_mgr,
        stage_checkpoint_guard=stage_checkpoint_guard,
        progress_emitter=progress_emitter,
        error_emitter=error_emitter,
        post_completion_hooks=post_hooks,
    )

    outcome = await scheduler.run()

    # Recon validator: the legacy code returned ``1`` from this
    # function when ``recon_validation`` was FAILED.  The actor
    # scheduler does not itself abort on this condition (it only
    # aborts on critical stage failures), so the exit-code policy is
    # enforced here, before the orchestrator's own resolver runs.
    if (
        outcome.exit_code is None
        and ctx.result.stage_status.get("recon_validation")
        == StageStatus.FAILED.value
    ):
        if not getattr(args, "dry_run", False):
            logger.error("Recon validation failed: no discoverable URLs found.")
            error_emitter(
                "recon_validation",
                "Recon validation failed: no discoverable URLs found.",
            )
            return 1
        ctx.result.stage_status["recon_validation"] = StageStatus.COMPLETED.value

    return outcome.exit_code


def resolve_pipeline_exit_code(
    orchestrator: Any,
    *,
    ctx: PipelineContext,
    config: Any,
    started_at: float,
    progress_emitter: Any,
) -> int:
    """Compute the final exit code for the pipeline run."""
    import time

    duration = time.time() - started_at
    findings_count = len(ctx.result.reportable_findings)

    if ctx.result.stage_status.get("recon_validation") == StageStatus.FAILED.value:
        metrics = ctx.result.module_metrics.get("recon_validation", {})
        if metrics.get("fatal", True):
            return 1

    for recon_stage in ("subdomains", "live_hosts", "urls"):
        if ctx.result.stage_status.get(recon_stage) == StageStatus.FAILED.value:
            metrics = ctx.result.module_metrics.get(recon_stage, {})
            if metrics.get("fatal", True):
                return 1

    if getattr(ctx.result, "cancel_requested", False):
        progress_emitter("shutdown", "Pipeline cancelled by user", 100, status="stopped")
        return 130

    progress_emitter(
        "shutdown",
        f"Pipeline execution complete. Found {findings_count} finding(s).",
        100,
        status="completed",
        details={"duration_seconds": round(duration, 2), "findings": findings_count},
    )
    return 0
