"""Thin PipelineOrchestrator that delegates to stage runners."""

import argparse
import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any, TypedDict
from src.core.checkpoint import (
    StageCheckpointGuard,
    attempt_recovery,
    create_checkpoint_manager,
    generate_run_id,
)
from src.core.config import load_config
from src.core.contracts.pipeline_runtime import PipelineInput, StageOutput
from src.core.events import EVENT_SCHEMA_VERSION, EventBus, EventType, get_event_bus
from src.core.logging.pipeline_logging import emit_error
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.middleware import OutboundRequestInterceptor, ScopeValidator
from src.core.models.stage_result import PipelineContext, StageResult
from src.core.utils import normalize_scope_entry
from src.infrastructure.observability.event_subscribers import register_event_metrics_subscribers
from src.pipeline.cache import cache_enabled
from src.pipeline.retry import RetryMetrics, RetryPolicy
from src.pipeline.runner_support import (
    build_tool_status,
    emit_progress,
)
from src.pipeline.services.output_store import PipelineOutputStore
from src.pipeline.services.pipeline_flow import pipeline_flow_manifest
from src.pipeline.services.plugin_catalog import resolve_stage_runner
from src.pipeline.storage import read_scope
from . import parallel
from ._constants import (
    DEFAULT_ITERATION_LIMIT,
    PIPELINE_STAGES,
    STAGE_ORDER,
)
from ._orchestrator_helpers import build_stage_methods_map, finalize_run, stage_baseline
from ._run_execution import execute_remaining_stages, resolve_pipeline_exit_code
from ._stage_retry import run_stage_with_retry
from ._state_helpers import (
    build_stage_input_contract,
    log_live_hosts_timeout_diagnostics,
    merge_stage_output,
    record_stage_post_run,
    resolve_stage_timeout,
    safe_checkpoint_stage_outcome,
)
from src.infrastructure.notifications.manager import ManagerConfig, NotificationManager
from src.infrastructure.observability.audit_subscriber import register_audit_subscriber
from src.infrastructure.observability.learning_subscriber import register_learning_subscriber
from src.infrastructure.observability.notification_subscriber import (
    register_notification_subscriber,
)
from src.infrastructure.observability.progress_subscriber import register_progress_subscriber
from src.learning.integration import LearningIntegration






class FindingDict(TypedDict, total=False):
    """TypedDict representing a finding dictionary from pipeline analysis."""

    category: str
    title: str
    url: str
    severity: str
    confidence: float
    score: int
    evidence: dict[str, Any]
    signals: list[str]


__all__ = [
    "PipelineOrchestrator",
    "PIPELINE_STAGES",
    "STAGE_ORDER",
    "DEFAULT_ITERATION_LIMIT",
]


logger = get_pipeline_logger(__name__)


class PipelineOrchestrator:
    """Orchestrates the security testing pipeline execution."""

    def __init__(self, event_bus: EventBus | None = None) -> None:
        self._stage_retry_policy: RetryPolicy | None = None
        self._stage_retry_metrics: RetryMetrics = RetryMetrics()
        self._event_bus: EventBus = event_bus or get_event_bus()

        # Register Observability Subscribers
        register_event_metrics_subscribers(self._event_bus)
        register_progress_subscriber(self._event_bus)

        # Register Cross-cutting Concern Subscribers
        register_audit_subscriber(self._event_bus)

        # Notifications (using default config for now, can be updated in run())
        self._notification_manager = NotificationManager(ManagerConfig())
        register_notification_subscriber(self._event_bus, self._notification_manager)

        # Learning
        self._learning_integration = LearningIntegration.get_or_create()
        register_learning_subscriber(self._event_bus, self._learning_integration)

        self._pipeline_input: PipelineInput | None = None
        self._pipeline_correlation_id: str = ""

    def _get_stage_retry_policy(self, config: Any) -> RetryPolicy:
        if self._stage_retry_policy is None:
            self._stage_retry_policy = RetryPolicy.from_settings(
                global_settings=getattr(config, "retry", None),
                tool_settings=None,
            )
        return self._stage_retry_policy

    @staticmethod
    def _stage_baseline(stage_name: str) -> int:
        return stage_baseline(stage_name, STAGE_ORDER)

    @staticmethod
    def _coerce_positive_int(value: Any) -> int | None:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None
        return parsed if parsed > 0 else None

    def _resolve_stage_timeout(
        self,
        stage_name: str,
        config: Any,
        ctx: PipelineContext,
    ) -> int:
        return resolve_stage_timeout(self, stage_name, config, ctx)

    def _log_live_hosts_timeout_diagnostics(
        self,
        ctx: PipelineContext,
        timeout: int,
    ) -> None:
        log_live_hosts_timeout_diagnostics(ctx, timeout)

    def _emit_event(self, event_type: EventType, source: str, data: dict[str, Any]) -> None:
        """Emit a pipeline domain event while keeping orchestration failure-safe."""
        # Enrich event data with common fields if available
        enriched_data = {
            "event_schema_version": EVENT_SCHEMA_VERSION,
            **(data or {}),
        }
        if self._pipeline_input:
            enriched_data.setdefault("target", self._pipeline_input.target_name)
            enriched_data.setdefault("target_name", self._pipeline_input.target_name)
            enriched_data.setdefault("run_id", self._pipeline_input.run_id)

        try:
            self._event_bus.emit(
                event_type,
                source=source,
                data=enriched_data,
                correlation_id=self._pipeline_correlation_id or None,
            )
        except (TypeError, ValueError, AttributeError) as exc:
            logger.warning("Failed to emit event %s from %s: %s", event_type.value, source, exc)

    def _emit_pipeline_error(self, reason: str, details: dict[str, Any] | None = None) -> None:
        self._emit_event(
            EventType.PIPELINE_ERROR,
            source="pipeline_orchestrator",
            data={"reason": reason, "details": details or {}},
        )

    def _build_stage_input_contract(
        self,
        stage_name: str,
        ctx: PipelineContext,
        config: Any | None = None,
    ) -> dict[str, Any]:
        return build_stage_input_contract(self, stage_name, ctx, config)

    def _build_stage_output_contract(
        self,
        stage_name: str,
        duration_seconds: float,
        ctx: PipelineContext,
    ) -> dict[str, Any]:
        return ctx.build_stage_output(stage_name, duration_seconds).to_dict()

    def _merge_stage_output(
        self,
        ctx: PipelineContext,
        stage_name: str,
        stage_output: StageOutput,
    ) -> None:
        merge_stage_output(ctx, stage_name, stage_output, wal=getattr(self, "_wal", None))

    @staticmethod
    def _safe_checkpoint_stage_outcome(
        checkpoint_mgr: Any,
        stage_name: str,
        stage_state: str,
        stage_metrics: Any,
    ) -> None:
        safe_checkpoint_stage_outcome(checkpoint_mgr, stage_name, stage_state, stage_metrics)

    def run_sync(self, args: argparse.Namespace) -> int:
        """Run the full security testing pipeline."""
        return asyncio.run(self.run(args))

    async def _finalize_run(self, exit_code: int) -> int:
        return await finalize_run(event_bus=self._event_bus, exit_code=exit_code, logger_obj=logger)

    def _build_stage_methods(self) -> dict[str, Any]:
        return build_stage_methods_map(
            stage_order=STAGE_ORDER,
            module_globals=globals(),
            resolve_stage_runner_func=resolve_stage_runner,
        )

    async def _execute_remaining_stages(
        self,
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
    ) -> int | None:
        return await execute_remaining_stages(
            self,
            remaining_stages=remaining_stages,
            stage_methods=stage_methods,
            args=args,
            config=config,
            ctx=ctx,
            scope_interceptor=scope_interceptor,
            nuclei_available=nuclei_available,
            checkpoint_mgr=checkpoint_mgr,
            handled_by_parallel=handled_by_parallel,
            stage_checkpoint_guard=StageCheckpointGuard,
            progress_emitter=emit_progress,
            error_emitter=emit_error,
        )

    def _resolve_pipeline_exit_code(
        self,
        *,
        ctx: PipelineContext,
        config: Any,
        started_at: float,
    ) -> int:
        return resolve_pipeline_exit_code(
            self,
            ctx=ctx,
            config=config,
            started_at=started_at,
            progress_emitter=emit_progress,
        )

    async def run(self, args: argparse.Namespace) -> int:
        """Run the full security testing pipeline with distributed concurrency protection."""
        flow_manifest = pipeline_flow_manifest()
        emit_progress("startup", "Loading configuration", 3)

        preloaded_config = getattr(args, "_loaded_config", None)
        config = preloaded_config if preloaded_config is not None else load_config(Path(args.config).resolve())

        # ──────────────────────────────────────────────────────────
        # Distributed Concurrency Guard (Overhaul #4)
        # ──────────────────────────────────────────────────────────
        from src.infrastructure.cache import CacheManager
        from src.infrastructure.cache.config import CacheConfig

        # Use common settings for cache paths if not in config
        cache_db_path = getattr(config, "cache_db_path", str(config.output_dir / "cache" / "cache_layer.db"))
        cache_dir = getattr(config, "cache_dir", str(config.output_dir / "cache" / "files"))
        redis_url = getattr(config, "redis_url", os.getenv("REDIS_URL"))

        cache_config = CacheConfig(
            sqlite_db_path=cache_db_path,
            cache_dir=cache_dir,
            redis_url=redis_url,
        )
        cache_mgr = CacheManager(config=cache_config)

        target_name = str(getattr(config, "target_name", "unknown") or "unknown")

        # Attempt to acquire a global lock for this target to prevent multi-worker collisions
        logger.info("Acquiring distributed lock for target: %s", target_name)
        lock_token = cache_mgr.acquire_recon_lock(target_name, ttl=3600, wait_timeout=5.0)

        if not lock_token and config.redis_url:
            logger.error("Failed to acquire distributed lock: Target '%s' is already being scanned by another worker.", target_name)
            emit_progress("startup", f"Collision: {target_name} is already under active scan", 0, status="failed")
            self._emit_pipeline_error("distributed_lock_collision", {"target": target_name})
            return 1

        try:
            return await self._run_secured(args, config, flow_manifest, cache_mgr)
        finally:
            if lock_token:
                logger.info("Releasing distributed lock for target: %s", target_name)
                cache_mgr.release_recon_lock(target_name, lock_token)
            cache_mgr.close()

    async def _run_secured(self, args: argparse.Namespace, config: Any, flow_manifest: Any, cache_mgr: Any) -> int:
        """Internal execution loop after lock acquisition."""
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
            print(
                json.dumps({"scope_entries": scope_entries, "tool_status": tool_status}, indent=2)
            )
            return await self._finalize_run(0)

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
        )

        run_id = generate_run_id()
        checkpoint_mgr = create_checkpoint_manager(
            Path(config.output_dir),
            config.target_name,
            run_id=run_id,
            storage_config=config.storage,
        )

        # ──────────────────────────────────────────────────────────
        # Distributed Write-Ahead Log (Overhaul #9)
        # ──────────────────────────────────────────────────────────
        from src.core.frontier.wal import FrontierWAL
        self._wal = FrontierWAL(config.redis_url, run_id)
        logger.info("Frontier WAL initialized: stream=cyber:wal:%s", run_id)

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
        self._pipeline_correlation_id = run_id
        self._pipeline_input = PipelineInput(
            target_name=str(getattr(config, "target_name", "unknown") or "unknown"),
            scope_entries=tuple(scope_entries),
            run_id=run_id,
            metadata={
                "use_cache": bool(getattr(ctx.result, "use_cache", use_cache)),
                "discovery_enabled": bool(
                    getattr(ctx.result, "discovery_enabled", discovery_enabled)
                ),
                "flow_stage_count": len(flow_manifest),
            },
        )
        self._emit_event(
            EventType.PIPELINE_STARTED,
            source="pipeline_orchestrator",
            data={
                "contract": self._pipeline_input.to_dict(),
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

        # Hook 1: Apply learning adaptations from previous runs
        try:
            from src.learning.integration import LearningIntegration

            learning = LearningIntegration.get_or_create(ctx.to_dict())
            adaptations = learning.compute_adaptations(ctx.to_dict())
            if adaptations:
                learning.apply_adaptations(ctx.to_dict(), adaptations)
                ctx.result.module_metrics.setdefault("learning", {})["feedback_applied"] = True
                logger.info("Applied %d learning adaptations from previous runs", len(adaptations))
        except Exception as exc:
            logger.warning("Learning adaptation failed: %s", exc)

        stage_methods = self._build_stage_methods()
        remaining_stages = [s for s in remaining_stages if s in stage_methods]

        nuclei_status: Any = tool_status.get("nuclei", {})
        nuclei_available = isinstance(nuclei_status, dict) and nuclei_status.get("available", False)

        # Track which parallel stages have been handled by the parallel runner
        handled_by_parallel: set[str] = set()
        stage_execution_exit = await self._execute_remaining_stages(
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
            return await self._finalize_run(stage_execution_exit)

        exit_code = self._resolve_pipeline_exit_code(
            ctx=ctx,
            config=config,
            started_at=started_at,
        )
        return await self._finalize_run(exit_code)

    # ------------------------------------------------------------------ parallel helpers --

    def _build_parallel_graph(self) -> dict[str, list[str]]:
        return parallel.build_parallel_graph()

    def _resolve_parallel_group(
        self,
        stage_name: str,
        nuclei_available: bool,
        remaining_stages: list[str],
    ) -> list[str] | None:
        return parallel.resolve_parallel_group(stage_name, nuclei_available, remaining_stages)

    def _all_deps_met(
        self,
        stage: str,
        completed: set[str],
        graph: dict[str, list[str]],
    ) -> bool:
        return parallel.all_deps_met(stage, completed, graph)

    async def _run_parallel_group(
        self,
        stages: list[str],
        stage_methods: dict[str, Any],
        args: argparse.Namespace,
        config: Any,
        ctx: PipelineContext,
        scope_interceptor: Any,
        nuclei_available: bool,
        checkpoint_mgr: Any,
        handled_by_parallel: set[str],
    ) -> None:
        await parallel.run_parallel_group(
            self,
            stages,
            stage_methods,
            args,
            config,
            ctx,
            scope_interceptor,
            nuclei_available,
            checkpoint_mgr,
            handled_by_parallel,
        )

    # ------------------------------------------------------------------ stage execution --

    async def _run_stage_with_retry(
        self,
        stage_name: str,
        method: Any,
        args: argparse.Namespace,
        config: Any,
        ctx: PipelineContext,
        timeout: int,
        scope_interceptor: Any,
        previous_deltas: list[dict[str, Any]] | None = None,
    ) -> StageOutput | None:
        return await run_stage_with_retry(
            self,
            stage_name,
            method,
            args,
            config,
            ctx,
            timeout,
            scope_interceptor,
            emit_progress,
            previous_deltas=previous_deltas,
        )

    async def _record_stage_post_run(
        self,
        stage_name: str,
        ctx: PipelineContext,
        checkpoint_mgr: Any,
        target_name: str,
    ) -> None:
        _ = target_name
        await record_stage_post_run(stage_name, ctx, checkpoint_mgr)


def find_previous_run(target_root: Path) -> Path | None:
    """Find the previous run directory for trend analysis."""
    from src.reporting import find_previous_run as _find_previous_run

    return _find_previous_run(target_root)
