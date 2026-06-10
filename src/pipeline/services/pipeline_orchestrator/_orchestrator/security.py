"""Security scanner execution runtime and target isolation guard."""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any, cast

from src.core.checkpoint import (
    attempt_recovery,
    create_checkpoint_manager,
    generate_run_id,
)
from src.core.contracts.pipeline_runtime import PipelineInput
from src.core.events import EventType
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.middleware import OutboundRequestInterceptor, ScopeValidator
from src.core.models.stage_result import PipelineContext, StageResult
from src.core.utils import normalize_scope_entry
from src.pipeline.cache import cache_enabled
from src.pipeline.runner_support import (
    emit_progress,
    load_adaptive_config,
)
from src.pipeline.services.output_store import PipelineOutputStore

from .._constants import STAGE_ORDER

logger = get_pipeline_logger(__name__)

# Minimum checkpoint_version we know how to read. Bump this whenever
# the persisted context shape changes incompatibly. Older checkpoints
# are refused at recovery time (see ``run_secured``).
CHECKPOINT_MIN_VERSION = 2
CHECKPOINT_CURRENT_VERSION = 2


def find_previous_run(target_root: Path) -> Path | None:
    """Find the previous run directory for trend analysis."""
    from src.reporting import find_previous_run as _find_previous_run

    return cast(Path | None, _find_previous_run(target_root))


def _merge_and_diff_scopes(
    ctx: PipelineContext, recovered_completed_stages: set[str], current_scope: list[str]
) -> None:
    """Three-way merge/diff logic for scan scopes at resume start."""
    old_scope = set(ctx.result.scope_entries or [])
    new_scope = set(current_scope)

    if old_scope == new_scope:
        return

    added = new_scope - old_scope
    removed = old_scope - new_scope

    logger.info("Scope change detected on resume: added=%s, removed=%s", added, removed)

    def _is_in_scope(item_str: str, active_scope: list[str]) -> bool:
        from urllib.parse import urlparse

        parsed = urlparse(item_str)
        host = parsed.netloc or parsed.path or item_str
        host = host.split(":")[0].strip().lower()
        for domain in active_scope:
            domain = domain.strip().lower()
            if host == domain or host.endswith("." + domain):
                return True
        return False

    if removed:
        # Filter subdomains, urls, and live hosts
        filtered_subdomains = {s for s in ctx.subdomains if _is_in_scope(s, current_scope)}
        filtered_urls = {u for u in ctx.urls if _is_in_scope(u, current_scope)}
        ctx.live_hosts = {h for h in ctx.live_hosts if _is_in_scope(h, current_scope)}

        # Filter findings
        filtered_findings = [
            f
            for f in ctx.reportable_findings
            if _is_in_scope(f.get("url", "") or f.get("target", ""), current_scope)
        ]
        ctx.result.waf_findings = [
            f
            for f in ctx.result.waf_findings
            if _is_in_scope(f.get("url", "") or f.get("target", ""), current_scope)
        ]
        ctx.result.nuclei_findings = [
            f
            for f in ctx.result.nuclei_findings
            if _is_in_scope(f.get("url", "") or f.get("target", ""), current_scope)
        ]
        ctx.result.merged_findings = [
            f
            for f in ctx.result.merged_findings
            if _is_in_scope(f.get("url", "") or f.get("target", ""), current_scope)
        ]

        # Re-initialize the CRDT neural state from the filtered data
        from src.core.frontier.state import NeuralState

        new_state = NeuralState()
        new_state.apply_delta(
            {
                "subdomains": list(filtered_subdomains),
                "urls": list(filtered_urls),
                "findings": list(filtered_findings),
            }
        )
        ctx.result._neural_state = new_state
        ctx.subdomains = filtered_subdomains
        ctx.urls = filtered_urls
        ctx.reportable_findings = filtered_findings

    # Update active scope in context

    ctx.result.scope_entries = list(current_scope)

    if added:
        # Reset completed recon stages so they re-run to collect data on added targets
        logger.info("Resetting completed stages to execute on added scope targets: %s", added)
        # Reset subdomains, live_hosts, urls so they re-execute on new targets
        for stage in {"subdomains", "live_hosts", "urls"}:
            recovered_completed_stages.discard(stage)


async def run_secured(
    orchestrator: Any,
    args: argparse.Namespace,
    config: Any,
    flow_manifest: Any,
    cache_mgr: Any,
    scope_entries: list[str],
    tool_status: dict[str, Any],
) -> int:
    started_at = time.time()
    force_fresh = getattr(args, "force_fresh_run", False)
    can_recover, recovered_state = attempt_recovery(
        Path(config.output_dir),
        config.target_name,
        force_fresh=force_fresh,
        storage_config=config.storage,
    )

    ctx = None
    checkpoint_mgr = None
    run_id = None
    remaining_stages: list[str] = []
    recovered_completed_stages = set()

    if can_recover and recovered_state:
        rec_run_id = recovered_state.pipeline_run_id
        recovered_checkpoint_mgr = create_checkpoint_manager(
            Path(config.output_dir),
            config.target_name,
            run_id=rec_run_id,
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
            # Validate the checkpoint is for the same target AND a
            # compatible schema version. The previous implementation
            # accepted any payload with these two top-level keys, so a
            # stale checkpoint from a previous run with the same target
            # name would be silently resumed — replaying thousands of
            # stages against a stale world.
            payload_target = str(recovered_payload.get("target_name", "")).strip()
            payload_version = recovered_payload.get("checkpoint_version", 0)
            try:
                payload_version_int = int(payload_version)
            except (TypeError, ValueError):
                payload_version_int = 0
            if payload_target and payload_target != config.target_name:
                logger.warning(
                    "Skipping checkpoint recovery for run=%s: target mismatch (%r != %r)",
                    rec_run_id,
                    payload_target,
                    config.target_name,
                )
            elif payload_version_int < CHECKPOINT_MIN_VERSION:
                logger.warning(
                    "Skipping checkpoint recovery for run=%s: checkpoint_version %s is below "
                    "supported minimum %s",
                    rec_run_id,
                    payload_version_int,
                    CHECKPOINT_MIN_VERSION,
                )
            else:
                logger.info(
                    "Recovering from full context checkpoint: run=%s completed_stages=%s",
                    rec_run_id,
                    recovered_state.completed_stages,
                )
                ctx = PipelineContext.restore(recovered_payload)
                _merge_and_diff_scopes(ctx, recovered_completed_stages, scope_entries)
                checkpoint_mgr = recovered_checkpoint_mgr
                orchestrator._checkpoint_mgr = checkpoint_mgr
                run_id = rec_run_id
                remaining_stages = [
                    stage for stage in STAGE_ORDER if stage not in recovered_completed_stages
                ]

        else:
            logger.warning(
                "Skipping checkpoint recovery for run=%s: incompatible checkpoint payload "
                "missing pipeline context fields",
                rec_run_id,
            )

    if run_id is None:
        run_id = generate_run_id()
        remaining_stages = list(STAGE_ORDER)

    output_store = PipelineOutputStore.create(
        config.output_dir,
        config.target_name,
        config.output,
        storage_config=config.storage,
        run_id=run_id,
    )

    use_cache = cache_enabled(config.cache)
    if ctx is not None:
        ctx.output_store = output_store
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
        previous_run = find_previous_run(output_store.target_root)
        module_metrics: dict[str, Any] = {}
        module_metrics["pipeline_flow"] = {
            "status": "ok",
            "stage_count": len(flow_manifest),
        }
        output_store.write_scope(scope_entries)
        discovery_enabled = any(
            config.tools.get(name) for name in ("subfinder", "assetfinder", "amass")
        )
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
        checkpoint_mgr = create_checkpoint_manager(
            Path(config.output_dir),
            config.target_name,
            run_id=run_id,
            storage_config=config.storage,
        )
        orchestrator._checkpoint_mgr = checkpoint_mgr

        if can_recover and recovered_state:
            # We had attempt_recovery positive but incompatible payload
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

    # Distributed Write-Ahead Log (WAL)
    from src.core.frontier.wal import FrontierWAL

    wal_aof_dir = Path(config.output_dir) / ".wal"
    orchestrator._wal = FrontierWAL(
        getattr(config, "redis_url", None),
        run_id,
        aof_dir=wal_aof_dir,
    )
    logger.info("Frontier WAL initialized: stream=cyber:wal:%s aof_dir=%s", run_id, wal_aof_dir)

    # Ghost-Actor Migration Handler (Graceful Degradation in non-Redis mode)
    if getattr(config, "redis_url", None) and cache_mgr._redis is not None:
        from src.core.frontier.ghost_actor import GhostMeshCoordinator
        from src.core.frontier.ghost_actor_registry import GhostMeshRegistry

        from ..migration_handler import ProactiveMigrationHandler

        mesh_registry = GhostMeshRegistry(cache_mgr._redis, run_id)
        coordinator = GhostMeshCoordinator(mesh_registry, getattr(cache_mgr, "_gossip", None))

        orchestrator._migration_handler = ProactiveMigrationHandler(
            coordinator=coordinator,
            check_interval_seconds=float(getattr(config, "migration_check_interval", 30.0)),
        )
        await orchestrator._migration_handler.start()
    else:
        orchestrator._migration_handler = None
        logger.info("Ghost-Actor Mesh deactivated: running in single-node/no-Redis mode")

    scope_entries = list(ctx.scope_entries)
    orchestrator._pipeline_correlation_id = run_id
    orchestrator._pipeline_input = PipelineInput(
        target_name=str(getattr(config, "target_name", "unknown") or "unknown"),
        scope_entries=tuple(scope_entries),
        run_id=run_id,
        metadata={
            "use_cache": bool(getattr(ctx.result, "use_cache", use_cache)),
            "discovery_enabled": bool(
                getattr(ctx.result, "discovery_enabled", ctx.result.discovery_enabled)
            ),
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

    # Apply learning adaptations exactly ONCE
    adaptations = {}
    try:
        from src.learning.integration import LearningIntegration

        ctx_dict = ctx.to_dict()
        learning = LearningIntegration.get_or_create(ctx_dict)
        adaptations = learning.compute_adaptations(ctx_dict)
    except Exception as exc:
        logger.warning("Learning compute_adaptations failed: %s", exc)

    if not adaptations:
        adaptive_config = load_adaptive_config(Path(config.output_dir), config.target_name)
        if adaptive_config:
            adaptations = adaptive_config

    if adaptations:
        ctx_dict = ctx.to_dict()
        import inspect

        sig = inspect.signature(orchestrator._learning_integration.apply_adaptations)
        if "config" in sig.parameters:
            orchestrator._learning_integration.apply_adaptations(
                ctx_dict, adaptations, config=config
            )
        else:
            orchestrator._learning_integration.apply_adaptations(ctx_dict, adaptations)
        ctx.result.module_metrics.setdefault("learning", {})["feedback_applied"] = True
        logger.info("Applied learning adaptations for target: %s", config.target_name)

    stage_methods = orchestrator._build_stage_methods()
    remaining_stages = [s for s in remaining_stages if s in stage_methods]

    nuclei_status: Any = tool_status.get("nuclei", {})
    if isinstance(nuclei_status, dict):
        nuclei_available = nuclei_status.get("available", False)
    else:
        nuclei_available = bool(nuclei_status)

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
        args=args,
    )
    return cast(int, await orchestrator._finalize_run(exit_code, ctx=ctx, config=config))
