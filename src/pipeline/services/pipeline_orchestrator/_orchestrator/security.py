"""Security scanner execution runtime and target isolation guard."""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any, cast

from src.core.contracts.pipeline_runtime import PipelineInput
from src.core.events import EventType
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.middleware import OutboundRequestInterceptor, ScopeValidator
from src.core.models.stage_result import PipelineContext, StageResult
from src.core.utils import normalize_scope_entry
from src.pipeline.runner_support import (
    emit_progress,
    load_adaptive_config,
)
from src.pipeline.services.output_store import PipelineOutputStore
from src.pipeline.unified_cache import cache_enabled

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


def generate_run_id() -> str:
    """Generate a unique run ID string."""
    from src.core.checkpoint import generate_run_id as _gen

    return _gen()


def create_checkpoint_manager(*args: Any, **kwargs: Any) -> Any:
    from src.core.checkpoint import create_checkpoint_manager as _ccm

    return _ccm(*args, **kwargs)


def attempt_recovery(*args: Any, **kwargs: Any) -> Any:
    from src.core.checkpoint import attempt_recovery as _ar

    return _ar(*args, **kwargs)


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
    pre_recovered_state: Any | None = None,
) -> int:
    from src.core.checkpoint import create_checkpoint_manager
    from src.core.recovery import RecoveryManager, WalReplayMode

    started_at = time.time()
    force_fresh = getattr(args, "force_fresh_run", False)
    resume_from = getattr(args, "resume_from", None) or getattr(config, "_resume_from", None)
    wal_replay = getattr(args, "wal_replay", None) or "replay"

    # Defect 1 fix: Acquire distributed run lock before recovery to prevent
    # split-brain when multiple processes attempt recovery for the same target.
    recovery_lock = None
    if not force_fresh:
        try:
            from src.infrastructure.task_pool import RunLock

            recovery_lock = RunLock(
                cache_dir=Path(config.output_dir) / ".locks",
                redis_url=getattr(config, "redis_url", None),
            )
            lock_key = f"recovery:{config.target_name}"
            if not recovery_lock.acquire(lock_key, ttl_seconds=7200):
                logger.error(
                    "Could not acquire recovery lock for target '%s'; "
                    "another process is recovering. Aborting to avoid split-brain.",
                    config.target_name,
                )
                return 1
        except Exception as exc:  # noqa: BLE001
            logger.debug("Recovery lock acquisition failed (non-fatal): %s", exc)
            recovery_lock = None

    recovery = RecoveryManager(
        Path(config.output_dir),
        config.target_name,
        redis_url=getattr(config, "redis_url", None),
        storage_config=config.storage,
        stage_order=STAGE_ORDER,
        min_checkpoint_version=CHECKPOINT_MIN_VERSION,
    )
    reconstructed = recovery.recover(
        force_fresh=force_fresh,
        resume_from=resume_from,
        wal_replay=wal_replay,
        pre_recovered_state=pre_recovered_state,
    )
    can_recover = reconstructed.can_recover
    recovered_state = reconstructed.checkpoint
    recovered_payload = reconstructed.context_payload
    recovered_completed_stages = set(reconstructed.completed_stages)
    remaining_stages = list(reconstructed.remaining_stages)
    run_id = reconstructed.run_id
    checkpoint_mgr = reconstructed.checkpoint_mgr
    orchestrator._wal = reconstructed.wal
    ctx = None

    if can_recover and recovered_state and recovered_payload is not None:
        logger.info(
            "Recovery Manager: snapshot+journal resume run=%s source=%s completed=%s",
            run_id,
            reconstructed.source,
            recovered_state.completed_stages,
        )
        ctx = PipelineContext.restore(recovered_payload)
        _merge_and_diff_scopes(ctx, recovered_completed_stages, scope_entries)
        remaining_stages = [
            stage for stage in STAGE_ORDER if stage not in recovered_completed_stages
        ]
        if checkpoint_mgr is not None:
            checkpoint_mgr.save_context_snapshot("_scope_merge", ctx.to_dict())
        wal = reconstructed.wal
        if wal is not None and hasattr(wal, "compact_after_snapshot"):
            try:
                from src.core.frontier.state import NeuralState

                snap_state = getattr(ctx.result, "_neural_state", None)
                if isinstance(snap_state, NeuralState):
                    wal.compact_after_snapshot(snap_state, keep_entries=500)
            except Exception as exc:  # noqa: BLE001
                logger.debug("WAL compaction after scope merge failed: %s", exc)
        orchestrator._checkpoint_mgr = checkpoint_mgr
    elif recovered_state is not None:
        logger.warning(
            "Recovery Manager: skipping snapshot for run=%s: incompatible or missing context",
            recovered_state.pipeline_run_id,
        )

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

    if getattr(orchestrator, "_wal", None) is None:
        from src.infrastructure.frontier.wal import FrontierWAL

        wal_aof_dir = Path(config.output_dir) / ".wal"
        orchestrator._wal = FrontierWAL(
            getattr(config, "redis_url", None),
            run_id,
            aof_dir=wal_aof_dir,
        )
    try:
        from src.core.frontier.authority_runtime import attach_pipeline_authority

        attach_pipeline_authority(orchestrator, run_id, config)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Pipeline authority runtime attach failed: %s", exc)
    logger.info(
        "Recovery Manager: WAL journal ready stream=cyber:wal:%s source=%s mode=%s",
        run_id,
        reconstructed.source,
        reconstructed.mode.value,
    )
    wal_state = reconstructed.wal_state
    if (
        wal_state is not None
        and ctx is not None
        and ctx.result is not None
        and hasattr(ctx.result, "_neural_state")
    ):
        # Capture the pre-merge cursor. After merge, last_wal_id advances
        # to the latest recovered CRDT entry and a second pass keyed off
        # that cursor would drop post-checkpoint journal fields.
        journal_cursor = ctx.result._neural_state.last_wal_id
        journal_exclude = set(ctx.result._neural_state.applied_wal_ids)
        if hasattr(ctx.result, "_journal_applied_ids"):
            ctx.result._journal_applied_ids.update(journal_exclude)
        ctx.result._neural_state.merge(wal_state)
        # Replay non-CRDT fields only (live_hosts, parameters,
        # module_metrics, merged_findings). Never call unfiltered
        # recover_deltas() + apply_state_delta(): list.extend is not
        # idempotent and would double-apply already-snapshotted rows.
        wal = getattr(orchestrator, "_wal", None)
        apply_fields = getattr(ctx.result, "apply_journal_fields", None)
        if wal is not None and hasattr(wal, "recover_deltas") and callable(apply_fields):
            try:
                for entry in wal.recover_deltas(journal_cursor, exclude_ids=journal_exclude):
                    delta = entry.get("delta") if isinstance(entry, dict) else None
                    if isinstance(delta, dict):
                        delta.setdefault("_wal_id", entry.get("id"))
                        apply_fields(delta)
            except Exception as exc:  # noqa: BLE001
                logger.debug("WAL apply_journal_fields replay failed: %s", exc)
        ctx.subdomains = ctx.result._neural_state.subdomains.to_set()
        ctx.urls = ctx.result._neural_state.urls.to_set()
        ctx.reportable_findings = list(ctx.result._neural_state.findings.values())
        logger.info(
            "WAL journal applied: %d subdomains, %d urls, %d findings (run %s)",
            len(ctx.subdomains),
            len(ctx.urls),
            len(ctx.reportable_findings),
            run_id,
        )
    if reconstructed.mode is WalReplayMode.VERIFY and reconstructed.verify_report:
        logger.info("WAL verify report: %s", reconstructed.verify_report)

    # Ghost-Actor Migration Handler (Graceful Degradation in non-Redis mode)
    if getattr(config, "redis_url", None) and cache_mgr._redis is not None:
        from src.infrastructure.frontier.ghost_actor import GhostMeshCoordinator
        from src.infrastructure.frontier.ghost_actor_registry import GhostMeshRegistry

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

    # Defect 1 fix: Release the recovery lock now that recovery and
    # checkpoint setup are complete. Subsequent writes are protected by
    # the CheckpointManager's own lock.
    if recovery_lock is not None:
        try:
            recovery_lock.release()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Recovery lock release failed (non-fatal): %s", exc)
        recovery_lock = None

    runtime = getattr(orchestrator, "_authority_runtime", None)
    if runtime is not None and ctx is not None:
        ctx.budget_enforcer = runtime.hunt_budget
        ctx.authority_runtime = runtime

    stage_methods = orchestrator._build_stage_methods()
    remaining_stages = [s for s in remaining_stages if s in stage_methods]
    from src.pipeline.stage_plan import constrain_remaining_stages

    remaining_stages = constrain_remaining_stages(
        remaining_stages,
        config=config,
        selected_modules=getattr(config, "enabled_modules", None),
    )

    if getattr(args, "dry_run", False) or not reconstructed.execute_stages:
        logger.info(
            "Dry-run / WAL dry-run: reconstructed source=%s remaining=%s; skipping stage execution.",
            reconstructed.source,
            remaining_stages,
        )
        print(
            f"Dry run complete. source={reconstructed.source} "
            f"remaining_stages={remaining_stages} scope_entries: {scope_entries}",
            flush=True,
        )
        emit_progress("startup", "Dry-run complete", 100, status="completed")
        return 0

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
