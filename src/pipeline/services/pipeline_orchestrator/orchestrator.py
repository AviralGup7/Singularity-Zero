"""Thin PipelineOrchestrator that delegates to stage runners."""

import argparse
import asyncio
import concurrent.futures
import os
from typing import Any, TypedDict, cast

from src.core.checkpoint import (
    StageCheckpointGuard,
    attempt_recovery,  # noqa: F401 – module-namespace seam
    create_checkpoint_manager,  # noqa: F401 – module-namespace seam
    generate_run_id,  # noqa: F401 – module-namespace seam
)
from src.core.contracts.pipeline_runtime import PipelineInput, StageOutput
from src.core.events import EVENT_SCHEMA_VERSION, EventBus, EventType, get_event_bus
from src.core.logging.pipeline_logging import emit_error
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.infrastructure.notifications.manager import ManagerConfig, NotificationManager
from src.infrastructure.observability.audit_subscriber import register_audit_subscriber
from src.infrastructure.observability.event_subscribers import register_event_metrics_subscribers
from src.infrastructure.observability.learning_subscriber import register_learning_subscriber
from src.infrastructure.observability.notification_subscriber import (
    register_notification_subscriber,
)
from src.infrastructure.observability.progress_subscriber import register_progress_subscriber
from src.learning.integration import LearningIntegration
from src.pipeline.cache import cache_enabled  # noqa: F401 – module-namespace seam
from src.pipeline.retry import (
    AdaptiveBackoffHeuristic,
    RetryMetrics,
    RetryPolicy,
    StageRetryPolicy,
)
from src.pipeline.runner_support import (
    build_tool_status,  # noqa: F401 – module-namespace seam
    emit_progress,
    load_adaptive_config,  # noqa: F401 – module-namespace seam
)
from src.pipeline.services.output_store import PipelineOutputStore  # noqa: F401 – seam
from src.pipeline.services.plugin_catalog import resolve_stage_runner
from src.pipeline.services.stage_registry import pipeline_flow_manifest  # noqa: F401 – seam
from src.pipeline.storage import read_scope  # noqa: F401 – module-namespace seam

from . import parallel
from ._constants import (
    DEFAULT_ITERATION_LIMIT,
    PIPELINE_STAGES,
    STAGE_ORDER,
)
from ._orchestrator import (
    build_stage_input_contract,
    build_stage_methods_map,
    finalize_run,
    log_live_hosts_timeout_diagnostics,
    merge_stage_output,
    record_stage_post_run,
    resolve_stage_timeout,
    run_stage_with_retry,
    safe_checkpoint_stage_outcome,
    stage_baseline,
)
from ._orchestrator.security import find_previous_run  # noqa: F401 – monkeypatch seam
from ._run_execution import execute_remaining_stages, resolve_pipeline_exit_code
from .migration_handler import ProactiveMigrationHandler


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


class ExecutionContext:
    """Manages the run inputs, variables, correlation IDs, run paths, output stores, and checkpoint managers."""

    def __init__(self) -> None:
        self.pipeline_input: PipelineInput | None = None
        self.pipeline_correlation_id: str = ""
        self.checkpoint_mgr: Any = None
        self.wal: Any = None


class ObservabilityBus:
    """Manages registering of subscribers (event metrics, progress, audit, notification, learning) and emitting events."""

    def __init__(self, event_bus: EventBus) -> None:
        self._event_bus = event_bus
        register_event_metrics_subscribers(self._event_bus)
        register_progress_subscriber(self._event_bus)
        register_audit_subscriber(self._event_bus)

        self.notification_manager = NotificationManager(ManagerConfig())
        register_notification_subscriber(self._event_bus, self.notification_manager)

        self.learning_integration = LearningIntegration.get_or_create()
        register_learning_subscriber(self._event_bus, self.learning_integration)

    def emit_event(
        self,
        event_type: EventType,
        source: str,
        data: dict[str, Any],
        pipeline_input: PipelineInput | None,
        correlation_id: str,
    ) -> None:
        enriched_data = {
            "event_schema_version": EVENT_SCHEMA_VERSION,
            **(data or {}),
        }
        if pipeline_input:
            enriched_data.setdefault("target", pipeline_input.target_name)
            enriched_data.setdefault("target_name", pipeline_input.target_name)
            enriched_data.setdefault("run_id", pipeline_input.run_id)

        try:
            self._event_bus.emit(
                event_type,
                source=source,
                data=enriched_data,
                correlation_id=correlation_id or None,
            )
        except (TypeError, ValueError, AttributeError) as exc:
            logger.warning("Failed to emit event %s from %s: %s", event_type.value, source, exc)


class StageDispatcher:
    """Manages sequential and parallel runner groups, and legacy monkeypatch lookups."""

    def build_stage_methods(self) -> dict[str, Any]:
        return build_stage_methods_map(
            stage_order=STAGE_ORDER,
            module_globals=globals(),
            resolve_stage_runner_func=resolve_stage_runner,
        )


class PipelineOrchestrator:
    """Orchestrates the security testing pipeline execution."""

    def __init__(self, event_bus: EventBus | None = None) -> None:
        self._stage_retry_policy: StageRetryPolicy | None = None
        self._stage_retry_metrics: RetryMetrics = RetryMetrics()
        self._event_bus: EventBus = event_bus or get_event_bus()

        # Extracted dedicated services
        self.observability_bus = ObservabilityBus(self._event_bus)
        self.ctx = ExecutionContext()
        self.dispatcher = StageDispatcher()

        self._migration_handler: ProactiveMigrationHandler | None = None

    @property
    def _pipeline_input(self) -> PipelineInput | None:
        return self.ctx.pipeline_input

    @_pipeline_input.setter
    def _pipeline_input(self, val: PipelineInput | None) -> None:
        self.ctx.pipeline_input = val

    @property
    def _pipeline_correlation_id(self) -> str:
        return self.ctx.pipeline_correlation_id

    @_pipeline_correlation_id.setter
    def _pipeline_correlation_id(self, val: str) -> None:
        self.ctx.pipeline_correlation_id = val

    @property
    def _checkpoint_mgr(self) -> Any:
        return self.ctx.checkpoint_mgr

    @_checkpoint_mgr.setter
    def _checkpoint_mgr(self, val: Any) -> None:
        self.ctx.checkpoint_mgr = val

    @property
    def _wal(self) -> Any:
        return self.ctx.wal

    @_wal.setter
    def _wal(self, val: Any) -> None:
        self.ctx.wal = val

    @property
    def _learning_integration(self) -> LearningIntegration:
        return self.observability_bus.learning_integration

    def _get_stage_retry_policy(self, config: Any) -> StageRetryPolicy:
        if self._stage_retry_policy is None:
            raw = RetryPolicy.from_settings(
                global_settings=getattr(config, "retry", None),
                tool_settings=None,
            )
            self._stage_retry_policy = StageRetryPolicy(
                base_policy=raw,
                adaptive_heuristic=AdaptiveBackoffHeuristic(),
                max_retry_budget_seconds=getattr(
                    getattr(config, "retry", None), "max_retry_budget_seconds", 0.0
                ),
            )
        return self._stage_retry_policy

    @staticmethod
    def _stage_baseline(stage_name: str) -> int:
        return stage_baseline(stage_name, STAGE_ORDER)

    @staticmethod
    def _coerce_positive_int(value: Any) -> int | None:
        from ._orchestrator.utils import coerce_positive_int

        return coerce_positive_int(value)

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
        self.observability_bus.emit_event(
            event_type,
            source=source,
            data=data,
            pipeline_input=self.ctx.pipeline_input,
            correlation_id=self.ctx.pipeline_correlation_id,
        )

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
        return cast(dict[str, Any], build_stage_input_contract(self, stage_name, ctx, config))

    def _build_stage_output_contract(
        self,
        stage_name: str,
        duration_seconds: float,
        ctx: PipelineContext,
    ) -> dict[str, Any]:
        return cast(dict[str, Any], ctx.build_stage_output(stage_name, duration_seconds).to_dict())

    def _merge_stage_output(
        self,
        ctx: PipelineContext,
        stage_name: str,
        stage_output: StageOutput,
    ) -> None:
        merge_stage_output(ctx, stage_name, stage_output, wal=getattr(self, "_wal", None))

        # Emit finding creation events
        if stage_output.state_delta:
            findings = stage_output.state_delta.get("reportable_findings", [])
            if isinstance(findings, (list, tuple)):
                for finding in findings:
                    self._emit_event(
                        EventType.FINDING_CREATED,
                        source=f"stage.{stage_name}",
                        data={"finding": finding},
                    )

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
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            coro = self.run(args)
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            try:
                return future.result(timeout=3600)
            except concurrent.futures.TimeoutError:
                logger.error("Pipeline run timed out waiting for event loop")
                return 1
        else:
            return asyncio.run(self.run(args))

    async def _finalize_run(
        self,
        exit_code: int,
        ctx: PipelineContext | None = None,
        config: Any | None = None,
    ) -> int:
        if self._migration_handler:
            await self._migration_handler.stop()

        event_data: dict[str, Any] = {"exit_code": exit_code}
        if config:
            event_data["target"] = str(getattr(config, "target_name", "unknown"))
        if ctx:
            event_data["run_id"] = ctx.run_id
            event_data["ctx"] = ctx.to_dict()
            summary = getattr(ctx.result, "summary", ctx.result.__dict__.get("summary"))
            if summary:
                event_data["ctx"]["summary"] = summary
                if "compliance" in summary:
                    event_data["compliance"] = summary["compliance"]

        self._emit_event(
            EventType.PIPELINE_COMPLETE,
            source="orchestrator",
            data=event_data,
        )
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
        args: argparse.Namespace | None = None,
    ) -> int:
        return resolve_pipeline_exit_code(
            self,
            ctx=ctx,
            config=config,
            started_at=started_at,
            progress_emitter=emit_progress,
            args=args,
        )

    async def run(self, args: argparse.Namespace) -> int:
        """Run the full security testing pipeline with distributed concurrency protection."""
        from ._orchestrator.bootstrap import bootstrap_pipeline

        config, scope_entries, tool_status, flow_manifest = bootstrap_pipeline(args)
        setattr(args, "_loaded_config", config)
        setattr(args, "_loaded_scope_entries", scope_entries)

        # ──────────────────────────────────────────────────────────
        # Distributed Concurrency Guard (Overhaul #4)
        # ──────────────────────────────────────────────────────────
        from src.infrastructure.cache import CacheManager
        from src.infrastructure.cache.config import CacheConfig

        # Use common settings for cache paths if not in config
        cache_db_path = getattr(
            config, "cache_db_path", str(config.output_dir / "cache" / "cache_layer.db")
        )
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
        import asyncio

        lock_token = await asyncio.to_thread(
            cache_mgr.acquire_recon_lock, target_name, ttl=3600, wait_timeout=5.0
        )

        if not lock_token:
            if getattr(config, "redis_url", None) and cache_mgr._redis is not None:
                logger.error(
                    "Failed to acquire distributed lock: Target '%s' is already being scanned by another worker.",
                    target_name,
                )
                emit_progress(
                    "startup",
                    f"Collision: {target_name} is already under active scan",
                    0,
                    status="failed",
                )
                self._emit_pipeline_error("distributed_lock_collision", {"target": target_name})
                return 1
            else:
                logger.warning(
                    "No distributed lock acquired for target '%s'. Running in single-node mode without Redis. "
                    "Concurrent workers may collide.",
                    target_name,
                )

        try:
            return await self._run_secured(
                args, config, flow_manifest, cache_mgr, scope_entries, tool_status
            )
        finally:
            if lock_token:
                logger.info("Releasing distributed lock for target: %s", target_name)
                cache_mgr.release_recon_lock(target_name, lock_token)
            cache_mgr.close()

    async def _run_secured(
        self,
        args: argparse.Namespace,
        config: Any,
        flow_manifest: Any,
        cache_mgr: Any,
        scope_entries: list[str],
        tool_status: dict[str, Any],
    ) -> int:
        """Internal execution loop after lock acquisition."""
        from ._orchestrator.security import run_secured

        return await run_secured(
            self, args, config, flow_manifest, cache_mgr, scope_entries, tool_status
        )

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
        # 🛸 Sprint 1: Register for proactive migration monitoring
        actor_id = f"actor:{stage_name}:{ctx.run_id}"
        # Note: In a real actor-based execution, the 'method' or 'stage_runner'
        # would be encapsulated in a ScanActor instance. For now, we register
        # the current stage execution context if the handler is active.
        if self._migration_handler:
            # We use the method as a proxy for the 'actor' logic for now.
            # In a full Ghost-Actor implementation, this would be a pykka.ActorRef.
            self._migration_handler.register_actor(actor_id, method)

        try:
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
        finally:
            if self._migration_handler:
                self._migration_handler.unregister_actor(actor_id)

    async def _record_stage_post_run(
        self,
        stage_name: str,
        ctx: PipelineContext,
        checkpoint_mgr: Any,
    ) -> None:
        await record_stage_post_run(stage_name, ctx, checkpoint_mgr)

    async def _execute_single_stage(
        self,
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
    ) -> int | str | None:
        """Execute a single stage under the actor scheduler.

        Wraps ``_run_stage_with_retry`` with the lifecycle event
        emission, checkpoint guard, post-run checkpoint record, and
        fatal-recon detection that the legacy tier runner used to
        provide.  The actor scheduler calls this method once per
        dispatched node; the return value is informational and
        interpreted by :class:`ActorScheduler`.
        """
        import time

        from src.core.models.stage_result import StageStatus

        from ._constants import PIPELINE_STAGES
        from ._orchestrator import metrics_indicate_fatal_failure

        stage_started = time.time()

        progress_emitter(
            stage_name,
            f"Neural-Mesh: Entering {PIPELINE_STAGES.get(stage_name, stage_name)}",
            self._stage_baseline(stage_name),
            status="running",
            stage_status="running",
            event_trigger="stage_transition",
        )
        self._emit_event(
            EventType.STAGE_STARTED,
            source=f"stage.{stage_name}",
            data={"contract": self._build_stage_input_contract(stage_name, ctx, config)},
        )

        timeout = self._resolve_stage_timeout(stage_name, config, ctx)

        previous_deltas: list[dict[str, Any]] = []
        if hasattr(checkpoint_mgr, "load_stage_deltas"):
            previous_deltas = checkpoint_mgr.load_stage_deltas(stage_name)

        with stage_checkpoint_guard(checkpoint_mgr, stage_name):
            if getattr(ctx.result, "cancel_requested", False):
                return None

            try:
                stage_output = await self._run_stage_with_retry(
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
                    self._merge_stage_output(ctx, stage_name, stage_output)
                    ctx.compact_state()
                    from src.pipeline.validation import validate_stage_artifact
                    is_valid, err_msg = validate_stage_artifact(stage_name, ctx)
                    if not is_valid:
                        raise RuntimeError(f"Stage output integrity validation failed: {err_msg}")

                elapsed = time.time() - stage_started

                await self._record_stage_post_run(stage_name, ctx, checkpoint_mgr)

                progress_emitter(
                    stage_name,
                    f"Neural-Mesh: Finished {PIPELINE_STAGES.get(stage_name, stage_name)}",
                    self._stage_baseline(stage_name),
                    status="completed",
                    stage_status="completed",
                    details={"duration_seconds": round(elapsed, 2)},
                    event_trigger="stage_complete",
                    stage_percent=100,
                )

                self._emit_event(
                    EventType.STAGE_COMPLETED,
                    source=f"stage.{stage_name}",
                    data={"contract": self._build_stage_output_contract(stage_name, elapsed, ctx)},
                )

                if stage_name in {"subdomains", "live_hosts", "urls"}:
                    stage_metrics = ctx.result.module_metrics.get(stage_name, {})
                    if metrics_indicate_fatal_failure(stage_metrics):
                        progress_emitter(
                            stage_name,
                            f"Stage failed: {PIPELINE_STAGES.get(stage_name, stage_name)}",
                            self._stage_baseline(stage_name),
                            status="failed",
                            stage_status="failed",
                            event_trigger="stage_failed",
                            error=stage_metrics.get("error", "Fatal recon failure"),
                        )
                        return 1

                return None

            except Exception as exc:
                logger.exception("Fatal failure in Neural-Mesh stage '%s'", stage_name)
                if "WAL durability layer failed" in str(exc):
                    return "WAL_FAILURE"
                ctx.result.stage_status[stage_name] = StageStatus.FAILED.value
                ctx.result.module_metrics[stage_name] = {
                    "status": "error",
                    "error": str(exc) or exc.__class__.__name__,
                    "failure_reason": str(exc) or exc.__class__.__name__,
                    "fatal": stage_name in {"subdomains", "live_hosts", "urls"},
                }
                return 1
