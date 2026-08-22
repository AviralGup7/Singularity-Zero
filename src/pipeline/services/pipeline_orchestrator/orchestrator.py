"""Thin PipelineOrchestrator that delegates to stage runners."""

import argparse
import asyncio
import concurrent.futures
import json
import os
from pathlib import Path
from typing import Any, TypedDict, cast

from src.core.contracts.pipeline_runtime import PipelineInput, StageOutput
from src.core.events import EventBus, EventType, get_event_bus
from src.core.logging.pipeline_logging import emit_error
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.infrastructure.notifications.manager import NotificationManager
from src.learning.integration import LearningIntegration


def _lazy_checkpoint_import(name: str):  # type: ignore[no-untyped-def]
    """Lazy-import from ``src.core.checkpoint`` to avoid circular import.

    The checkpoint package imports *this* module during its own initialisation,
    so we must not import it at the top level.
    """
    from src.core.checkpoint import (  # type: ignore[no-redef]
        StageCheckpointGuard,
        attempt_recovery,
        create_checkpoint_manager,
        generate_run_id,
    )

    _map = {
        "StageCheckpointGuard": StageCheckpointGuard,
        "attempt_recovery": attempt_recovery,
        "create_checkpoint_manager": create_checkpoint_manager,
        "generate_run_id": generate_run_id,
    }
    return _map[name]


from src.pipeline.retry import (
    AdaptiveBackoffHeuristic,
    RetryMetrics,
    RetryPolicy,
    StageRetryPolicy,
)
from src.pipeline.runner_support import (
    emit_progress,
)
from src.pipeline.services.plugin_catalog import resolve_stage_runner

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
from ._run_execution import execute_remaining_stages, resolve_pipeline_exit_code
from .execution_context import ExecutionContext
from .migration_handler import ProactiveMigrationHandler
from .observability_bus import ObservabilityBus
from .stage_dispatcher import StageDispatcher


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


def pipeline_flow_manifest() -> dict[str, Any]:
    """Return pipeline stage flow manifest detailing stage ordering and definitions."""
    return {
        "stages": list(STAGE_ORDER),
        "definitions": dict(PIPELINE_STAGES),
    }


def build_tool_status(config: Any) -> dict[str, bool]:
    """Build a dictionary of tool names and their availability or enabled status."""
    tools_cfg = getattr(config, "tools", {})
    if isinstance(tools_cfg, dict):
        return {str(k): bool(v) for k, v in tools_cfg.items()}
    return {}


def cache_enabled(config: Any) -> bool:
    """Return True if caching is enabled in config."""
    cache_cfg = getattr(config, "cache", {})
    if isinstance(cache_cfg, dict):
        return bool(cache_cfg.get("enabled", True))
    return True


def find_previous_run(target_dir: Any) -> Path | None:
    """Find the previous run directory for a target.

    Scans run directories and returns the most recent one that has a
    valid (parseable JSON) ``run_summary.json``.  Directories with
    missing or corrupted summaries are skipped so that a crash during
    artifact writing does not poison the previous-run diff.
    """
    path = Path(str(target_dir)) if not isinstance(target_dir, Path) else target_dir
    if not path.exists() or not path.is_dir():
        return None
    candidates = sorted(
        [d for d in path.iterdir() if d.is_dir() and not d.name.startswith("_")],
        key=lambda p: (p.stat().st_mtime, str(p)),
    )
    # Walk newest-first until we find one with a valid summary
    for candidate in reversed(candidates):
        summary_path = candidate / "run_summary.json"
        if not summary_path.exists():
            continue
        try:
            data = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("run_id"):
                return candidate
        except (json.JSONDecodeError, OSError, ValueError):
            logger.warning("Skipping corrupted run_summary.json in %s", candidate)
            continue
    return None


from src.pipeline.services.output_store import PipelineOutputStore


def generate_run_id() -> str:
    """Generate a unique run ID string."""
    fn = _lazy_checkpoint_import("generate_run_id")
    return fn()


def StageCheckpointGuard(*args: Any, **kwargs: Any) -> Any:  # noqa: N802
    # Intentionally class-cased: this is a lazy-import shim standing in
    # for the CLASS of the same name, and callers use it as a
    # constructor. Renaming it to snake_case would break every call
    # site and the substitution it exists to perform.
    cls = _lazy_checkpoint_import("StageCheckpointGuard")
    return cls(*args, **kwargs)


def create_checkpoint_manager(*args: Any, **kwargs: Any) -> Any:
    fn = _lazy_checkpoint_import("create_checkpoint_manager")
    return fn(*args, **kwargs)


def attempt_recovery(*args: Any, **kwargs: Any) -> Any:
    fn = _lazy_checkpoint_import("attempt_recovery")
    return fn(*args, **kwargs)


__all__ = [
    "ExecutionContext",
    "ObservabilityBus",
    "PipelineOrchestrator",
    "StageDispatcher",
    "PipelineOutputStore",
    "pipeline_flow_manifest",
    "build_tool_status",
    "cache_enabled",
    "find_previous_run",
    "generate_run_id",
    "StageCheckpointGuard",
    "create_checkpoint_manager",
    "attempt_recovery",
    "emit_progress",
    "stage_progress_kind",
    "resolve_stage_timeout",
    "run_stage_with_retry",
    "PIPELINE_STAGES",
    "STAGE_ORDER",
    "DEFAULT_ITERATION_LIMIT",
]


logger = get_pipeline_logger(__name__)

_FAILED_STAGE_MARKERS = frozenset(
    {"FAILED", "ERROR", "TIMEOUT", "failed", "error", "timeout"}
)
_SKIPPED_STAGE_MARKERS = frozenset(
    {
        "SKIPPED",
        "SKIPPED_DISABLED",
        "SKIPPED_FAILED",
        "skipped",
        "skip",
        "cancelled",
        "canceled",
    }
)


def stage_progress_kind(
    ctx: PipelineContext,
    stage_name: str,
    stage_output: StageOutput | None,
) -> str:
    """Classify the real stage outcome so we do not emit a fake completed event."""
    recorded = str(ctx.result.stage_status.get(stage_name, "") or "").strip()
    metrics = ctx.result.module_metrics.get(stage_name, {})
    metric_status = ""
    if isinstance(metrics, dict):
        metric_status = str(metrics.get("status") or "").strip()
    outcome = getattr(stage_output, "outcome", None)
    outcome_value = str(getattr(outcome, "value", outcome) or "").strip()
    tokens = {recorded, recorded.upper(), metric_status, metric_status.lower(), outcome_value, outcome_value.lower()}
    if tokens & _FAILED_STAGE_MARKERS:
        return "failed"
    if tokens & _SKIPPED_STAGE_MARKERS:
        return "skipped"
    return "completed"


class PipelineOrchestrator:
    """Orchestrates the security testing pipeline execution."""

    def __init__(
        self,
        event_bus: EventBus | None = None,
        notification_manager: NotificationManager | None = None,
        queue: Any | None = None,
    ) -> None:
        self._stage_retry_policy: StageRetryPolicy | None = None
        self._stage_retry_metrics: RetryMetrics = RetryMetrics()
        self._event_bus: EventBus = event_bus or get_event_bus()

        # Extracted dedicated services
        self.observability_bus = ObservabilityBus(self._event_bus, notification_manager)
        self.ctx = ExecutionContext()
        self.dispatcher = StageDispatcher(queue=queue)

        self._migration_handler: ProactiveMigrationHandler | None = None
        self._run_lock: Any = None
        self._run_lock_scan_id: str | None = None

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

    def _emit_event(
        self, event_type: EventType, source: str, data: dict[str, Any], trace_id: str | None = None
    ) -> None:
        """Emit a pipeline domain event while keeping orchestration failure-safe."""
        logger.debug("_emit_event start event_type=%s source=%s", event_type, source)
        try:
            _result = self.observability_bus.emit_event(
                event_type,
                source=source,
                data=data,
                pipeline_input=self.ctx.pipeline_input,
                correlation_id=self.ctx.pipeline_correlation_id,
                trace_id=trace_id,
            )
            logger.debug("_emit_event success event_type=%s", event_type)
        except Exception as exc:
            logger.debug("_emit_event failed event_type=%s exc=%s", event_type, exc)
            raise

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

        stage_trace_id = getattr(stage_output, "trace_id", "") or ""
        if stage_output.state_delta:
            findings = stage_output.state_delta.get("reportable_findings", [])
            if isinstance(findings, (list, tuple)):
                for finding in findings:
                    if isinstance(finding, dict):
                        str(
                            finding.get("finding_id")
                            or finding.get("id")
                            or finding.get("title", "")
                            or ""
                        )
                    self._emit_event(
                        EventType.FINDING_CREATED,
                        source=f"stage.{stage_name}",
                        data={"finding": finding, "trace_id": stage_trace_id},
                        trace_id=stage_trace_id,
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
            raise RuntimeError(
                "Cannot call run_sync() from the event loop thread while the loop is running; "
                "this would deadlock. Use asyncio.run() or call from a separate thread."
            )
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
        # Defect 2 fix: Wait for all in-flight checkpoint replications
        # to complete before tearing down, preventing data loss on shutdown.
        if self._checkpoint_mgr is not None:
            try:
                await self._checkpoint_mgr.wait_for_replications(timeout=15.0)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Checkpoint replication wait during finalize failed: %s", exc)

        # Defect 2 fix: Close WAL and wait for any pending WAL operations.
        wal = getattr(self, "_wal", None)
        if wal is not None:
            try:
                wal.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("WAL close during finalize failed: %s", exc)

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

        event_type = (
            EventType.PIPELINE_CANCELLED if exit_code == 130 else EventType.PIPELINE_COMPLETE
        )
        self._emit_event(
            event_type,
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
            stage_checkpoint_guard=_lazy_checkpoint_import("StageCheckpointGuard"),
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

    def _acquire_distributed_lock(
        self, target_name: str, owner_id: str | None = None
    ) -> str | None:
        from src.infrastructure.task_pool import RunLock

        scan_id = target_name
        run_lock = RunLock()
        acquired = run_lock.acquire(scan_id, owner_id=owner_id)
        if acquired:
            logger.info("Acquired run lock for target: %s", target_name)
            self._run_lock = run_lock
            self._run_lock_scan_id = scan_id
            return scan_id
        logger.error(
            "Failed to acquire run lock: Target '%s' is already under active scan.",
            target_name,
        )
        emit_progress(
            "startup",
            f"Collision: {target_name} is already under active scan",
            0,
            status="failed",
        )
        self._emit_pipeline_error("distributed_lock_collision", {"target": target_name})
        return None

    async def _release_distributed_lock(self) -> None:
        run_lock = getattr(self, "_run_lock", None)
        if run_lock is not None:
            run_lock.release()
            self._run_lock = None

    async def run(self, args: argparse.Namespace) -> int:
        """Run the full security testing pipeline with single-node concurrency protection."""
        from ._orchestrator.bootstrap import bootstrap_pipeline

        config, scope_entries, tool_status, flow_manifest = bootstrap_pipeline(args)
        self._loaded_config = config
        setattr(args, "_loaded_config", config)
        setattr(args, "_loaded_scope_entries", scope_entries)

        from src.infrastructure.cache import CacheManager
        from src.infrastructure.cache.config import CacheConfig

        output_dir_path = (
            Path(config.output_dir) if isinstance(config.output_dir, str) else config.output_dir
        )
        cache_db_path = getattr(
            config, "cache_db_path", str(output_dir_path / "cache" / "cache_layer.db")
        )
        cache_dir = getattr(config, "cache_dir", str(output_dir_path / "cache" / "files"))
        redis_url = getattr(config, "redis_url", os.getenv("REDIS_URL"))

        cache_config = CacheConfig(
            sqlite_db_path=cache_db_path,
            cache_dir=cache_dir,
            redis_url=redis_url,
        )
        cache_mgr = CacheManager(config=cache_config)

        target_name = str(getattr(config, "target_name", "unknown") or "unknown")

        force_fresh = getattr(args, "force_fresh_run", False)
        can_recover, recovered_state = _lazy_checkpoint_import("attempt_recovery")(
            Path(config.output_dir),
            config.target_name,
            force_fresh=force_fresh,
            storage_config=getattr(config, "storage", None),
        )
        owner_id = recovered_state.pipeline_run_id if recovered_state else None

        scan_id = self._acquire_distributed_lock(target_name, owner_id=owner_id)
        if not scan_id:
            cache_mgr.close()
            return 1

        exit_code = 3
        try:
            exit_code = await self._run_secured(
                args,
                config,
                flow_manifest,
                cache_mgr,
                scope_entries,
                tool_status,
                pre_recovered_state=recovered_state,
            )
            return exit_code
        finally:
            # Bug fix: Always release the lock regardless of exit code.
            # Previously, exit_code == 3 caused lock to be skipped on release,
            # which leaked the lock on unhandled exceptions that weren't mapped
            # to a non-3 exit code.
            await self._release_distributed_lock()
            cache_mgr.close()

    async def _run_secured(
        self,
        args: argparse.Namespace,
        config: Any,
        flow_manifest: Any,
        cache_mgr: Any,
        scope_entries: list[str],
        tool_status: dict[str, Any],
        pre_recovered_state: Any | None = None,
    ) -> int:
        """Internal execution loop after lock acquisition."""
        from ._orchestrator.security import run_secured

        return await run_secured(
            self,
            args,
            config,
            flow_manifest,
            cache_mgr,
            scope_entries,
            tool_status,
            pre_recovered_state=pre_recovered_state,
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

    async def _replay_single_stage(
        self, run_id: str, stage_name: str, trace_dir: str = ".ai/traces"
    ) -> StageOutput | None:
        from src.infrastructure.observability.trace_store import get_trace_store
        from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

        trace_store = get_trace_store(trace_dir=trace_dir)
        trace = trace_store.get_trace_for_stage(run_id, stage_name)
        if trace is None:
            logger.error("No trace found for run=%s stage=%s", run_id, stage_name)
            return None

        config = getattr(self, "_loaded_config", None) or getattr(self.ctx, "config", None)
        if config is None:
            logger.error("No config available for replay of run=%s stage=%s", run_id, stage_name)
            return None

        checkpoint_mgr = getattr(self, "_checkpoint_mgr", None)
        if checkpoint_mgr is None:
            from src.core.checkpoint import create_checkpoint_manager

            checkpoint_mgr = create_checkpoint_manager(
                Path(config.output_dir),
                config.target_name,
                run_id=run_id,
                storage_config=getattr(config, "storage", None),
            )
            self.ctx.checkpoint_mgr = checkpoint_mgr

        ctx_snapshot = checkpoint_mgr._load_context_snapshot_for_stage(stage_name)
        if not ctx_snapshot:
            logger.error("No context snapshot found for run=%s stage=%s", run_id, stage_name)
            return None

        from src.core.models.stage_result import PipelineContext, StageResult

        result = StageResult.from_dict(ctx_snapshot.get("result", {}))
        ctx = PipelineContext(
            result=result,
            output_store=getattr(self.ctx, "output_store", None),
            run_id=run_id,
        )

        stage_methods = self._build_stage_methods()
        method = stage_methods.get(stage_name)
        if method is None:
            logger.error("No stage method found for stage=%s", stage_name)
            return None

        build_stage_input_from_context(stage_name, config, ctx)
        scope_interceptor = getattr(self, "_scope_interceptor", None)
        timeout = self._resolve_stage_timeout(stage_name, config, ctx)

        logger.info(
            "Replaying stage %s for run %s (trace_id=%s)",
            stage_name,
            run_id,
            trace.trace_id,
        )
        return await self._run_stage_with_retry(
            stage_name,
            method,
            getattr(self.ctx, "args", None) or config,
            config,
            ctx,
            timeout,
            scope_interceptor,
            previous_deltas=[],
        )

    async def _replay_traces(
        self, run_id: str, trace_dir: str = ".ai/traces"
    ) -> list[StageOutput | None]:
        from src.infrastructure.observability.trace_store import get_trace_store

        trace_store = get_trace_store(trace_dir=trace_dir)
        traces = trace_store.get_traces_for_run(run_id)
        if not traces:
            logger.error("No traces found for run=%s", run_id)
            return []

        results: list[StageOutput | None] = []
        for trace in traces:
            logger.info("Replaying stage %s from trace %s", trace.stage_name, trace.trace_id)
            result = await self._replay_single_stage(run_id, trace.stage_name, trace_dir=trace_dir)
            results.append(result)
        return results

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
        critical: bool = False,
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
                critical=critical,
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
        critical: bool = False,
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
                progress_emitter(
                    stage_name,
                    f"Skipped stage {stage_name}: cancel requested",
                    self._stage_baseline(stage_name),
                    status="skipped",
                    stage_status="skipped",
                    reason="cancel_requested",
                    event_trigger="stage_skipped",
                )
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
                    critical=critical,
                )

                terminal = stage_progress_kind(ctx, stage_name, stage_output)
                if stage_output is not None and terminal != "failed":
                    self._merge_stage_output(ctx, stage_name, stage_output)
                    ctx.compact_state()
                    from src.pipeline.validation import validate_stage_artifact

                    is_valid, err_msg = validate_stage_artifact(stage_name, ctx)
                    if not is_valid:
                        raise RuntimeError(f"Stage output integrity validation failed: {err_msg}")

                elapsed = time.time() - stage_started

                await self._record_stage_post_run(stage_name, ctx, checkpoint_mgr)

                if terminal == "failed":
                    return 1
                if terminal == "skipped":
                    return None

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

                return None

            except Exception as exc:
                logger.exception("Fatal failure in Neural-Mesh stage '%s'", stage_name)
                error_text = str(exc) or exc.__class__.__name__
                reason = (
                    "WAL durability layer failed"
                    if "WAL durability layer failed" in str(exc)
                    else error_text
                )
                ctx.result.stage_status[stage_name] = StageStatus.FAILED.value
                ctx.result.module_metrics[stage_name] = {
                    "status": "error",
                    "error": error_text,
                    "failure_reason": reason,
                    "fatal": critical,
                }
                try:
                    progress_emitter(
                        stage_name,
                        f"Stage failed ({stage_name}): {reason}",
                        self._stage_baseline(stage_name),
                        status="error",
                        stage_status="error",
                        failed_stage=stage_name,
                        failure_reason=reason,
                        error=error_text,
                        event_trigger="stage_failed",
                        fatal=critical,
                    )
                except Exception:
                    logger.debug("Failed to emit error progress for %s", stage_name, exc_info=True)
                return 1
