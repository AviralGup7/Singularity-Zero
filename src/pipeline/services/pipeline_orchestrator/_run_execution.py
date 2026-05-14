import argparse
import asyncio
import time
from typing import Any

from src.core.events import EventType
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext, StageStatus

from ._constants import PIPELINE_STAGES
from .dag_engine import build_neural_mesh_dag

logger = get_pipeline_logger(__name__)

def _is_truthy_fatal(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes", "fatal")
    return bool(val)

def _metrics_indicate_fatal_failure(metrics: Any) -> bool:
    if not isinstance(metrics, dict):
        return False
    fatal_marker = metrics.get("fatal")
    if fatal_marker is None:
        # Backward compatibility: treat unspecified fatality as fatal.
        return True
    return _is_truthy_fatal(fatal_marker)

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
    """Execute the pipeline using the Neural-Mesh DAG execution engine."""
    # Build the dependency graph
    dag = build_neural_mesh_dag(stage_methods)
    execution_plan = dag.get_execution_order()
    
    logger.info("Neural-Mesh DAG Engine: Multi-tiered execution plan initialized")
    dag.visualize()

    completed_stages: set[str] = set()
    if hasattr(checkpoint_mgr, "completed_stages"):
        completed_stages.update(checkpoint_mgr.completed_stages)

    for tier_index, tier in enumerate(execution_plan):
        # Filter tier to only includes stages that still need to run
        active_tier = [s for s in tier if s in remaining_stages and s not in completed_stages]
        if not active_tier:
            continue

        logger.info("Executing Neural-Mesh Tier %d: %s", tier_index, active_tier)
        
        # Parallel execution of all stages in this tier
        tier_tasks = []
        for stage_name in active_tier:
            method = dag.get_method(stage_name)
            if not method:
                continue
                
            tier_tasks.append(
                _execute_single_stage(
                    orchestrator,
                    stage_name,
                    method,
                    args,
                    config,
                    ctx,
                    scope_interceptor,
                    checkpoint_mgr,
                    stage_checkpoint_guard,
                    progress_emitter,
                    error_emitter
                )
            )
        
        # Wait for all stages in the current tier to complete before moving to the next
        results = await asyncio.gather(*tier_tasks, return_exceptions=True)
        
        # Check for fatal failures in this tier
        for stage_name, res in zip(active_tier, results):
            if isinstance(res, Exception):
                logger.error("Stage '%s' failed with fatal error: %s", stage_name, res)
                error_emitter(stage_name, f"Neural-Mesh Tier Exception: {res}")
                if stage_name in {"subdomains", "live_hosts", "urls"}:
                    return 1 # Fatal recon failure stops the mesh
            elif res == 1 and stage_name in {"subdomains", "live_hosts", "urls"}:
                return 1

        completed_stages.update(active_tier)

    return None

async def _execute_single_stage(
    orchestrator: Any,
    stage_name: str,
    method: Any,
    args: argparse.Namespace,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any,
    checkpoint_mgr: Any,
    stage_checkpoint_guard: Any,
    progress_emitter: Any,
    error_emitter: Any,
) -> int | None:
    """Internal helper to execute a single stage within a DAG tier."""
    stage_started = time.time()
    
    # 1. Emit start progress
    progress_emitter(
        stage_name,
        f"Neural-Mesh: Entering {PIPELINE_STAGES.get(stage_name, stage_name)}",
        orchestrator._stage_baseline(stage_name),
        status="running",
        stage_status="running",
        event_trigger="stage_transition",
    )
    orchestrator._emit_event(
        EventType.STAGE_STARTED,
        source=f"stage.{stage_name}",
        data={"contract": orchestrator._build_stage_input_contract(stage_name, ctx, config)},
    )

    timeout = orchestrator._resolve_stage_timeout(stage_name, config, ctx)
    
    # Load incremental deltas for mid-stage resume support
    previous_deltas = []
    if hasattr(checkpoint_mgr, "load_stage_deltas"):
        previous_deltas = checkpoint_mgr.load_stage_deltas(stage_name)

    with stage_checkpoint_guard(checkpoint_mgr, stage_name):
        if getattr(ctx.result, "cancel_requested", False):
            return None

        try:
            stage_output = await orchestrator._run_stage_with_retry(
                stage_name,
                method,
                args,
                config,
                ctx,
                timeout,
                scope_interceptor,
                previous_deltas=previous_deltas,
            )
            
            if stage_output is not None:
                orchestrator._merge_stage_output(ctx, stage_name, stage_output)
                
            elapsed = time.time() - stage_started
            
            # Post-run recording
            await orchestrator._record_stage_post_run(stage_name, ctx, checkpoint_mgr, config.target_name)
            
            # 2. Emit completion progress
            progress_emitter(
                stage_name,
                f"Neural-Mesh: Finished {PIPELINE_STAGES.get(stage_name, stage_name)}",
                orchestrator._stage_baseline(stage_name),
                status="completed",
                stage_status="completed",
                details={"duration_seconds": round(elapsed, 2)},
                event_trigger="stage_complete",
                stage_percent=100
            )
            
            orchestrator._emit_event(
                EventType.STAGE_COMPLETED,
                source=f"stage.{stage_name}",
                data={"contract": orchestrator._build_stage_output_contract(stage_name, elapsed, ctx)},
            )

            # Fail fast check for recon
            if stage_name in {"subdomains", "live_hosts", "urls"}:
                stage_metrics = ctx.result.module_metrics.get(stage_name, {})
                if _metrics_indicate_fatal_failure(stage_metrics):
                    return 1
                    
            return None
            
        except Exception as exc:
            logger.exception("Fatal failure in Neural-Mesh stage '%s'", stage_name)
            return 1

def resolve_pipeline_exit_code(
    orchestrator: Any,
    *,
    ctx: PipelineContext,
    config: Any,
    started_at: float,
    progress_emitter: Any,
) -> int:
    """Compute the final exit code for the pipeline run."""
    duration = time.time() - started_at
    findings_count = len(ctx.result.reportable_findings)

    # If any recon stage failed, it's a critical failure (exit 1)
    for recon_stage in ["subdomains", "live_hosts", "urls"]:
        if ctx.result.stage_status.get(recon_stage) == StageStatus.FAILED.value:
            return 1

    # Check for cancellation
    if getattr(ctx.result, "cancel_requested", False):
        progress_emitter("shutdown", "Pipeline cancelled by user", 100, status="stopped")
        return 130

    # Otherwise successful (exit 0)
    progress_emitter(
        "shutdown",
        f"Pipeline execution complete. Found {findings_count} finding(s).",
        100,
        status="completed",
        details={"duration_seconds": round(duration, 2), "findings": findings_count},
    )
    return 0
