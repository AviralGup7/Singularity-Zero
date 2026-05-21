"""Security scanner execution runtime and target isolation guard."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, cast

import src.pipeline.services.pipeline_orchestrator.orchestrator as o
from src.core.contracts.pipeline_runtime import PipelineInput
from src.core.events import EventType
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.middleware import OutboundRequestInterceptor, ScopeValidator
from src.core.models.stage_result import PipelineContext, StageResult
from src.core.utils import normalize_scope_entry
from src.pipeline.services.output_store import PipelineOutputStore

from .._constants import STAGE_ORDER

logger = get_pipeline_logger(__name__)


def find_previous_run(target_root: Path) -> Path | None:
    """Find the previous run directory for trend analysis."""
    from src.reporting import find_previous_run as _find_previous_run

    return cast(Path | None, _find_previous_run(target_root))


async def run_secured(
    orchestrator: Any,
    args: argparse.Namespace,
    config: Any,
    flow_manifest: Any,
    cache_mgr: Any,
) -> int:
    """Securely execute the testing pipeline after acquiring target locks.

    Handles WAL logging, mesh coordinators, recovery checks, and error metrics.
    """
    attempt_recovery = getattr(o, "attempt_recovery")
    create_checkpoint_manager = getattr(o, "create_checkpoint_manager")
    generate_run_id = getattr(o, "generate_run_id")
    cache_enabled = getattr(o, "cache_enabled")
    emit_progress = getattr(o, "emit_progress")
    load_adaptive_config = getattr(o, "load_adaptive_config")
    read_scope = getattr(o, "read_scope")
    build_tool_status = getattr(o, "build_tool_status")
    preloaded_scope_entries = getattr(args, "_loaded_scope_entries", None)
    scope_entries = (
        list(preloaded_scope_entries)
        if preloaded_scope_entries is not None
        else read_scope(Path(args.scope).resolve())
    )
    screenshot_cfg = config.screenshots if isinstance(config.screenshots, dict) else {}
    tool_status = build_tool_status(screenshot_cfg.get("browser_paths", []))
    emit_progress("startup", f"Loaded config for {config.target_name}", 8)

    if args.dry_run:
        print(json.dumps({"scope_entries": scope_entries, "tool_status": tool_status}, indent=2))
        return cast(int, await orchestrator._finalize_run(0))

    started_at = time.time()
    output_store = PipelineOutputStore.create(
        config.output_dir, config.target_name, config.output, storage_config=config.storage
    )
    previous_run = find_previous_run(output_store.target_root)
    use_cache = cache_enabled(config.cache)
    module_metrics: dict[str, Any] = {}
    module_metrics["pipeline_flow"] = {
        "status": "ok",
        "stage_count": len(flow_manifest),
    }
    output_store.write_scope(scope_entries)
    discovery_enabled = any(
        config.tools.get(name) for name in ("subfinder", "assetfinder", "amass")
    )

    run_id = generate_run_id()
    ctx = PipelineContext(
        result=StageResult(
            scope_entries=list(scope_entries),
            use_cache=use_cache,
            module_metrics=module_metrics,
            previous_run=previous_run,
            tool_status=tool_status,
            flow_manifest=flow_manifest,  # type: ignore[arg-type]
            started_at=started_at,
            discovery_enabled=discovery_enabled,
        ),
        output_store=output_store,
        run_id=run_id,
    )

    # Load adaptive config (Phase 5.2)
    adaptive_config = load_adaptive_config(Path(config.output_dir), config.target_name)
    if adaptive_config:
        ctx_dict = ctx.to_dict()
        orchestrator._learning_integration.apply_adaptations(
            ctx_dict, adaptive_config, config=config
        )
        logger.info("Pre-applied adaptive configuration for target: %s", config.target_name)

    checkpoint_mgr = create_checkpoint_manager(
        Path(config.output_dir),
        config.target_name,
        run_id=run_id,
        storage_config=config.storage,
    )
    orchestrator._checkpoint_mgr = checkpoint_mgr

    # Distributed Write-Ahead Log (WAL)
    from src.core.frontier.wal import FrontierWAL

    orchestrator._wal = FrontierWAL(getattr(config, "redis_url", None), run_id)
    logger.info("Frontier WAL initialized: stream=cyber:wal:%s", run_id)

    # Ghost-Actor Migration Handler
    from src.core.frontier.ghost_actor import GhostMeshCoordinator, GhostMeshRegistry

    mesh_registry = GhostMeshRegistry(cache_mgr._redis, run_id)
    coordinator = GhostMeshCoordinator(mesh_registry, getattr(cache_mgr, "_gossip", None))

    # Note: ProactiveMigrationHandler is imported dynamically from a clean relative module.
    # We will locate/create this helper or just keep importing from .migration_handler.
    from ..migration_handler import ProactiveMigrationHandler

    orchestrator._migration_handler = ProactiveMigrationHandler(
        coordinator=coordinator,
        check_interval_seconds=float(getattr(config, "migration_check_interval", 30.0)),
    )
    await orchestrator._migration_handler.start()

    force_fresh = getattr(args, "force_fresh_run", False)
    can_recover, recovered_state = attempt_recovery(
        Path(config.output_dir),
        config.target_name,
        force_fresh=force_fresh,
        storage_config=config.storage,
    )
    if can_recover and recovered_state:
        recovered_checkpoint_mgr = create_checkpoint_manager(
            Path(config.output_dir),
            config.target_name,
            run_id=recovered_state.pipeline_run_id,
            storage_config=config.storage,
        )
        recovered_completed_stages = {
            str(stage).strip()
            for stage in (getattr(recovered_state, "completed_stages", []) or [])
            if str(stage).strip()
        }
        if hasattr(recovered_checkpoint_mgr, "load_latest_context_snapshot"):
            recovered_payload = recovered_checkpoint_mgr.load_latest_context_snapshot(
                recovered_completed_stages
            )
        else:
            recovered_payload = recovered_state.to_dict()
        if isinstance(recovered_payload, dict) and {
            "scope_entries",
            "stage_status",
        }.issubset(recovered_payload):
            logger.info(
                "Recovering from full context checkpoint: run=%s completed_stages=%s",
                recovered_state.pipeline_run_id,
                recovered_state.completed_stages,
            )
            ctx = PipelineContext.restore(recovered_payload)
            ctx.output_store = output_store
            checkpoint_mgr = recovered_checkpoint_mgr
            orchestrator._checkpoint_mgr = checkpoint_mgr
            run_id = recovered_state.pipeline_run_id
            remaining_stages = [
                stage for stage in STAGE_ORDER if stage not in recovered_completed_stages
            ]
            emit_progress(
                "startup",
                f"Recovered checkpoint run {run_id}; resuming {len(remaining_stages)} stage(s)",
                9,
                status="running",
                stage_status="running",
                details={
                    "checkpoint_run_id": run_id,
                    "completed_stage_count": len(recovered_completed_stages),
                },
            )
        else:
            logger.warning(
                "Skipping checkpoint recovery for run=%s: incompatible checkpoint payload "
                "missing pipeline context fields",
                recovered_state.pipeline_run_id,
            )
            emit_progress(
                "startup",
                "Skipping stale checkpoint recovery; starting a fresh run",
                9,
                status="warning",
                details={
                    "checkpoint_run_id": recovered_state.pipeline_run_id,
                    "reason": "incompatible_checkpoint_payload",
                },
            )
            remaining_stages = list(STAGE_ORDER)
    else:
        remaining_stages = list(STAGE_ORDER)

    scope_entries = list(ctx.scope_entries)
    orchestrator._pipeline_correlation_id = run_id
    orchestrator._pipeline_input = PipelineInput(
        target_name=str(getattr(config, "target_name", "unknown") or "unknown"),
        scope_entries=tuple(scope_entries),
        run_id=run_id,
        metadata={
            "use_cache": bool(getattr(ctx.result, "use_cache", use_cache)),
            "discovery_enabled": bool(getattr(ctx.result, "discovery_enabled", discovery_enabled)),
            "flow_stage_count": len(flow_manifest),
        },
    )
    orchestrator._emit_event(
        EventType.PIPELINE_STARTED,
        source="pipeline_orchestrator",
        data={
            "contract": orchestrator._pipeline_input.to_dict(),
        },
    )

    scope_hosts = {entry.strip().lower() for entry in scope_entries if entry.strip()}
    scope_hosts.update(
        {
            normalize_scope_entry(entry).strip().lower()
            for entry in scope_entries
            if normalize_scope_entry(entry).strip()
        }
    )
    scope_validator = ScopeValidator(scope_hosts)
    scope_interceptor = OutboundRequestInterceptor(scope_validator)

    # Apply learning adaptations
    try:
        from src.learning.integration import LearningIntegration

        ctx_dict = ctx.to_dict()
        learning = LearningIntegration.get_or_create(ctx_dict)
        adaptations = learning.compute_adaptations(ctx_dict)
        if adaptations:
            learning.apply_adaptations(ctx_dict, adaptations, config=config)
            ctx.result.module_metrics.setdefault("learning", {})["feedback_applied"] = True
            logger.info("Applied %d learning adaptations from previous runs", len(adaptations))
    except Exception as exc:
        logger.warning("Learning adaptation failed: %s", exc)

    stage_methods = orchestrator._build_stage_methods()
    remaining_stages = [s for s in remaining_stages if s in stage_methods]

    nuclei_status: Any = tool_status.get("nuclei", {})
    nuclei_available = isinstance(nuclei_status, dict) and nuclei_status.get("available", False)

    handled_by_parallel: set[str] = set()
    stage_execution_exit = await orchestrator._execute_remaining_stages(
        remaining_stages=remaining_stages,
        stage_methods=stage_methods,
        args=args,
        config=config,
        ctx=ctx,
        scope_interceptor=scope_interceptor,
        nuclei_available=nuclei_available,
        checkpoint_mgr=checkpoint_mgr,
        handled_by_parallel=handled_by_parallel,
    )
    if stage_execution_exit is not None:
        return cast(
            int, await orchestrator._finalize_run(stage_execution_exit, ctx=ctx, config=config)
        )

    exit_code = orchestrator._resolve_pipeline_exit_code(
        ctx=ctx,
        config=config,
        started_at=started_at,
    )
    return cast(int, await orchestrator._finalize_run(exit_code, ctx=ctx, config=config))
