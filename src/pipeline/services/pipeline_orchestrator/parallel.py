"""Parallel execution helpers for the PipelineOrchestrator.

This module contains the logic to build dynamic parallel graphs and run
parallel stage groups. It's an extracted subset of the functionality that
originally lived inside `orchestrator.py` to keep the orchestrator file
smaller and more focused.
"""

import asyncio
import time
from typing import Any

from src.core.checkpoint import StageCheckpointGuard
from src.core.events import EventType
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import StageStatus
from src.pipeline.runner_support import emit_progress

from ._constants import PARALLEL_STAGE_GROUPS, PIPELINE_STAGES, STAGE_DEPS, STAGE_ORDER

logger = get_pipeline_logger(__name__)


def build_parallel_graph() -> dict[str, list[str]]:
    """Build a parallel execution graph from STAGE_DEPS.

    For each stage, identify other stages that share the same dependencies
    and can therefore run in parallel after the dependency is satisfied.
    Returns a map: trigger_stage -> [parallel_candidates].
    """
    graph: dict[str, list[str]] = {}

    # After `urls` completes: `parameters` depends on {urls},
    # `ranking` depends on {urls, parameters} -> partial parallelism:
    # parameters can start immediately after urls; ranking waits for parameters
    graph["urls"] = ["parameters"]

    # After `passive_scan`: nuclei + access_control (already in PARALLEL_STAGE_GROUPS)
    graph["passive_scan"] = []  # handled by PARALLEL_STAGE_GROUPS

    return graph


def resolve_parallel_group(
    stage_name: str, nuclei_available: bool, remaining_stages: list[str]
) -> list[str] | None:
    """Resolve which stages can run in parallel after the given stage."""
    for trigger, paral_stages in PARALLEL_STAGE_GROUPS:
        if stage_name == trigger:
            return [
                s
                for s in paral_stages
                if s in remaining_stages and (s != "nuclei" or nuclei_available)
            ]
    return None


def all_deps_met(stage: str, completed: set[str], graph: dict[str, list[str]]) -> bool:
    deps = STAGE_DEPS.get(stage, set())
    return deps.issubset(completed)


async def run_parallel_group(
    orchestrator: Any,
    stages: list[str],
    stage_methods: dict[str, Any],
    args: Any,
    config: Any,
    ctx: Any,
    scope_interceptor: Any,
    nuclei_available: bool,
    checkpoint_mgr: Any,
    handled_by_parallel: set[str],
) -> None:
    """Run a group of stages concurrently with proper error handling.

    This mirrors the behavior implemented inside the orchestrator but keeps
    the parallel runner isolated from the large orchestrator file.
    """
    tasks: list[asyncio.Task[None]] = []
    stage_labels: list[str] = []

    for paral_stage in stages:
        if paral_stage in handled_by_parallel:
            continue
        if paral_stage == "nuclei" and not nuclei_available:
            logger.warning("Nuclei not on PATH, skipping from parallel group")
            ctx.result.module_metrics["nuclei"] = {
                "status": "skipped",
                "reason": "nuclei_not_on_path",
            }
            ctx.result.stage_status["nuclei"] = StageStatus.SKIPPED.value
            orchestrator._safe_checkpoint_stage_outcome(
                checkpoint_mgr,
                "nuclei",
                StageStatus.SKIPPED.value,
                ctx.result.module_metrics.get("nuclei", {}),
            )
            emit_progress(
                "nuclei",
                "Skipping nuclei: executable not found on PATH",
                orchestrator._stage_baseline("nuclei"),
                status="skipped",
                stage_status="skipped",
                reason="nuclei_not_on_path",
                failure_reason_code="nuclei_not_on_path",
                event_trigger="stage_skipped",
                next_best_action="Install nuclei binary or disable nuclei module before retrying.",
            )
            orchestrator._emit_event(
                EventType.STAGE_SKIPPED,
                source="stage.nuclei",
                data={"contract": orchestrator._build_stage_output_contract("nuclei", 0.0, ctx)},
            )
            handled_by_parallel.add("nuclei")
            continue

        paral_method = stage_methods.get(paral_stage)
        if paral_method is None:
            continue

        paral_timeout = orchestrator._resolve_stage_timeout(paral_stage, config, ctx)

        async def _wrapped(name: str, meth: Any, ts: int) -> None:
            started = time.time()
            findings_before = len(ctx.result.reportable_findings)
            try:
                logger.info(
                    "Starting pipeline stage: %s (target=%s)",
                    name,
                    getattr(config, "target_name", ""),
                )
                emit_progress(
                    name,
                    f"Entering stage: {PIPELINE_STAGES.get(name, name)}",
                    orchestrator._stage_baseline(name),
                    status="running",
                    stage_status="running",
                    stage_index=(STAGE_ORDER.index(name) + 1) if name in STAGE_ORDER else 0,
                    stage_total=len(STAGE_ORDER),
                    active_task_count=max(2, len(stages)),
                    event_trigger="stage_transition",
                )
                orchestrator._emit_event(
                    EventType.STAGE_STARTED,
                    source=f"stage.{name}",
                    data={"contract": orchestrator._build_stage_input_contract(name, ctx, config)},
                )
                with StageCheckpointGuard(checkpoint_mgr, name):
                    stage_output = await orchestrator._run_stage_with_retry(
                        name,
                        meth,
                        args,
                        config,
                        ctx,
                        ts,
                        scope_interceptor,
                    )
                    if stage_output is not None:
                        orchestrator._merge_stage_output(ctx, name, stage_output)

                    current_stage_state = str(
                        ctx.result.stage_status.get(name, StageStatus.COMPLETED.value)
                    )
                    orchestrator._safe_checkpoint_stage_outcome(
                        checkpoint_mgr,
                        name,
                        current_stage_state,
                        ctx.result.module_metrics.get(name, {}),
                    )
            except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
                logger.exception("Parallel stage %s raised an unhandled exception: %s", name, exc)
                ctx.result.stage_status[name] = StageStatus.FAILED.value
                ctx.result.module_metrics[name] = {
                    "status": "error",
                    "error": str(exc) or exc.__class__.__name__,
                    "failure_reason": str(exc) or exc.__class__.__name__,
                    "fatal": False,
                }
                orchestrator._safe_checkpoint_stage_outcome(
                    checkpoint_mgr,
                    name,
                    StageStatus.FAILED.value,
                    ctx.result.module_metrics.get(name, {}),
                )
            elapsed = time.time() - started
            logger.info("Stage completed: %s (%.1fs)", name, elapsed)
            await orchestrator._record_stage_post_run(
                name, ctx, checkpoint_mgr, getattr(config, "target_name", "")
            )
            stage_metrics = ctx.result.module_metrics.get(name, {})
            raw_state = str(ctx.result.stage_status.get(name, StageStatus.COMPLETED.value))
            status = "completed"
            if raw_state.upper() == StageStatus.FAILED.value:
                status = "error"
            elif raw_state.upper() == StageStatus.SKIPPED.value:
                status = "skipped"
            details: dict[str, Any] = {"duration_seconds": round(elapsed, 2)}
            if isinstance(stage_metrics, dict):
                metric_details = stage_metrics.get("details")
                if isinstance(metric_details, dict):
                    details.update(metric_details)

            stage_error_text = str(
                (stage_metrics.get("failure_reason") if isinstance(stage_metrics, dict) else "")
                or (stage_metrics.get("error") if isinstance(stage_metrics, dict) else "")
                or (stage_metrics.get("reason") if isinstance(stage_metrics, dict) else "")
                or ""
            ).strip()
            stage_event_trigger = "stage_complete"
            stage_message = f"Stage finished: {PIPELINE_STAGES.get(name, name)}"
            stage_progress_kwargs: dict[str, Any] = {"stage_percent": 100}
            if status == "error":
                stage_event_trigger = "stage_failed"
                stage_message = f"Stage failed: {PIPELINE_STAGES.get(name, name)}" + (
                    f" ({stage_error_text})" if stage_error_text else ""
                )
                stage_progress_kwargs = {}
            elif status == "skipped":
                stage_event_trigger = "stage_skipped"
                stage_message = f"Stage skipped: {PIPELINE_STAGES.get(name, name)}"

            emit_progress(
                name,
                stage_message,
                orchestrator._stage_baseline(name),
                status=status,
                stage_status=status,
                retry_count=int(
                    (stage_metrics.get("retry_count") if isinstance(stage_metrics, dict) else 0)
                    or 0
                ),
                reason=str(
                    (stage_metrics.get("reason") if isinstance(stage_metrics, dict) else "") or ""
                ),
                error=str(
                    (stage_metrics.get("error") if isinstance(stage_metrics, dict) else "") or ""
                ),
                details=details,
                active_task_count=max(1, len(stages) - 1),
                event_trigger=stage_event_trigger,
                **stage_progress_kwargs,
            )

            findings_after = len(ctx.result.reportable_findings)
            new_findings = max(0, findings_after - findings_before)
            if new_findings:
                orchestrator._emit_event(
                    EventType.FINDING_CREATED,
                    source=f"stage.{name}",
                    data={
                        "stage": name,
                        "new_findings": new_findings,
                        "total_findings": findings_after,
                    },
                )

            stage_output_contract = orchestrator._build_stage_output_contract(name, elapsed, ctx)
            if raw_state.upper() == StageStatus.FAILED.value:
                orchestrator._emit_event(
                    EventType.STAGE_FAILED,
                    source=f"stage.{name}",
                    data={"contract": stage_output_contract},
                )
            elif raw_state.upper() == StageStatus.SKIPPED.value:
                orchestrator._emit_event(
                    EventType.STAGE_SKIPPED,
                    source=f"stage.{name}",
                    data={"contract": stage_output_contract},
                )
            else:
                orchestrator._emit_event(
                    EventType.STAGE_COMPLETED,
                    source=f"stage.{name}",
                    data={"contract": stage_output_contract},
                )

        tasks.append(asyncio.create_task(_wrapped(paral_stage, paral_method, paral_timeout)))
        stage_labels.append(paral_stage)

    if len(tasks) < 2:
        # Less than 2 tasks — no real parallelism to gain, skip
        return

    await asyncio.gather(*tasks, return_exceptions=True)

    for paral_stage in stage_labels:
        handled_by_parallel.add(paral_stage)

    logger.info(
        "Parallel stages completed: %s",
        stage_labels,
    )
