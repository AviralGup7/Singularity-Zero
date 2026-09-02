"""Greedy per-node actor scheduler for the Neural-Mesh pipeline.

Replaces the legacy tier-batched runner with a readiness-driven loop:

1. On every tick, scan the graph for nodes whose ``needs`` are
   satisfied and whose ``when`` predicate is currently true.
2. Dispatch *all* ready nodes concurrently — no tier barrier, no
   artificial pipelining bubbles (speculative eager dispatch).
3. As soon as any in-flight task completes, re-evaluate readiness and
   dispatch newly-unblocked nodes immediately (this is the dynamic
   re-scheduling path: critical-path drift is absorbed naturally
   because we never wait for a full tier to drain).
4. Nodes whose ``when`` predicate never becomes true (e.g. an
   upstream stage produced no output) are recorded as
   ``SKIPPED`` with ``reason="condition_never_satisfied"`` and do
   not block downstream computation.

The scheduler emits stage lifecycle events at the same boundaries
the legacy tier runner did, so checkpoint files written by the old
code are still loadable by the new one and vice-versa.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import StageStatus
from src.jobs.run_outcome import EXIT_INFRA_FAILURE, EXIT_INTERRUPTED, EXIT_PARTIAL, EXIT_SUSPEND
from src.pipeline.runner_support import emit_stage_skipped

from ._graph_dsl import Graph, StageNode

logger = get_pipeline_logger(__name__)

# ---------------------------------------------------------------------------
# Telemetry event reasons
# ---------------------------------------------------------------------------
REASON_SPECULATIVE_DISPATCH = "speculative_dispatch"
REASON_RE_SCHEDULE = "re_schedule"
REASON_PRIORITY = "priority"

# Output size thresholds for dynamic re-balancing (purely advisory, safe by
# default for small scopes; can be overridden through config if needed)
DEFAULT_LARGE_OUTPUT_THRESHOLD = 1000
DEFAULT_REBALANCE_THRESHOLD_FACTOR = 2


def _effective_large_threshold(config: Any) -> int:
    try:
        candidate = getattr(config, "large_output_threshold", None)
        if isinstance(candidate, int) and candidate > 0:
            return candidate
    except (AttributeError, TypeError) as exc:  # noqa: BLE001 — broad catch intentional, config may be any type
        logger.debug("Failed to read large_output_threshold from config: %s", exc)
    return DEFAULT_LARGE_OUTPUT_THRESHOLD


def _is_large_output(stage_name: str, config: Any, ctx: Any) -> bool:
    try:
        value = getattr(ctx.result, stage_name, None)
    except AttributeError:
        return False
    if value is None:
        return False
    try:
        threshold = _effective_large_threshold(config)
    except (AttributeError, TypeError) as exc:  # noqa: BLE001 — broad catch intentional, config may be any type
        logger.debug("Failed to compute large output threshold: %s", exc)
        return False
    try:
        if hasattr(value, "__len__"):
            return len(value) >= threshold
    except TypeError as exc:
        logger.warning("Operation failed in actor_scheduler.py: %s", exc, exc_info=True)  # noqa: BLE001
    return False


def _downstream_for_rebalance(node: StageNode, graph: Graph) -> frozenset[str]:
    """Find nodes that depend on ``node`` (downstream), not nodes it depends on."""
    result: set[str] = set()
    queue: list[str] = [node.name]
    visited: set[str] = set()
    while queue:
        current_name = queue.pop()
        if current_name in visited:
            continue
        visited.add(current_name)
        for other in graph.nodes:
            if current_name in other.needs and other.name not in visited:
                result.add(other.name)
                queue.append(other.name)
    return frozenset(result)


@dataclass
class _ScheduledTask:
    """Bookkeeping for a single in-flight stage execution."""

    node: StageNode
    task: asyncio.Task[Any]
    started_at: float


@dataclass
class SchedulerOutcome:
    """Final result of a scheduler run."""

    exit_code: int | None = None
    completed: set[str] = field(default_factory=set)
    skipped: set[str] = field(default_factory=set)
    failed: set[str] = field(default_factory=set)
    speculative_dispatches: list[dict[str, Any]] = field(default_factory=list)
    re_schedules: list[dict[str, Any]] = field(default_factory=list)


class ActorScheduler:
    """Per-node readiness scheduler with speculative dispatch and re-scheduling.

    The scheduler is constructed once per run and discarded.  It holds
    no state between runs; checkpoint resume is handled by the
    caller, which seeds ``completed_stages`` and ``remaining_stages``.
    """

    def __init__(
        self,
        graph: Graph,
        stage_methods: Mapping[str, Callable[..., Awaitable[Any]]],
        *,
        ctx: Any,
        remaining_stages: list[str],
        completed_stages: set[str],
        orchestrator: Any,
        args: Any,
        config: Any,
        scope_interceptor: Any,
        nuclei_available: bool,
        checkpoint_mgr: Any,
        stage_checkpoint_guard: Any,
        progress_emitter: Callable[..., Any],
        error_emitter: Callable[..., Any],
        runtime_flags: Mapping[str, Any] | None = None,
        post_completion_hooks: Mapping[str, Callable[[Any], None]] | None = None,
    ) -> None:
        self._graph = graph
        self._stage_methods = dict(stage_methods)
        self._ctx = ctx
        self._remaining = set(remaining_stages)
        self._completed = set(completed_stages)
        self._orchestrator = orchestrator
        self._args = args
        self._config = config
        self._scope_interceptor = scope_interceptor
        self._nuclei_available = bool(nuclei_available)
        self._checkpoint_mgr = checkpoint_mgr
        self._stage_checkpoint_guard = stage_checkpoint_guard
        self._progress_emitter = progress_emitter
        self._error_emitter = error_emitter
        self._runtime_flags: dict[str, Any] = {
            "nuclei_available": self._nuclei_available,
        }
        if runtime_flags:
            self._runtime_flags.update(dict(runtime_flags))
        self._post_completion_hooks: dict[str, Callable[[Any], None]] = dict(
            post_completion_hooks or {}
        )
        self._in_flight: dict[asyncio.Task[Any], _ScheduledTask] = {}
        self._launched: set[str] = set()
        self._admission_gen = 0
        self._skipped: set[str] = set()
        self._deferred: set[str] = set()
        self._deferral_counts: dict[str, int] = {}
        self._max_deferrals: int = int(os.getenv("MAX_DEFERRALS_PER_NODE", "5"))
        self._injected: set[str] = set()
        self._failed_critical: str | None = None
        self._outcome = SchedulerOutcome()
        self._run_started_at = time.monotonic()
        max_duration = getattr(self._args, "max_duration_seconds", None)
        if max_duration is None:
            max_duration = getattr(self._config, "max_duration_seconds", None)
        try:
            self._max_duration_seconds = float(max_duration) if max_duration else None
        except (TypeError, ValueError):
            self._max_duration_seconds = None
        if self._max_duration_seconds is not None and self._max_duration_seconds <= 0:
            self._max_duration_seconds = None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> SchedulerOutcome:
        """Drive the scheduler to completion.

        Returns a :class:`SchedulerOutcome` summarising the run.  The
        caller (``execute_remaining_stages``) inspects ``exit_code``
        and decides whether to surface it to the CLI.
        """
        logger.info(
            "ActorScheduler: greedy readiness loop starting (%d nodes, %d pre-completed)",
            len(self._graph.nodes),
            len(self._completed),
        )
        try:
            from src.pipeline.mvr import bind_run

            bind_run(
                run_id=str(getattr(self._ctx, "run_id", "") or ""),
                output_dir=getattr(self._config, "output_dir", None),
                ctx=self._ctx,
            )
        except Exception:
            logger.debug("MVR bind_run skipped", exc_info=True)
        try:
            from pathlib import Path

            from src.core.checkpoint.dag_checkpoint import DagCheckpointStore
            from src.pipeline.graph_identity import (
                CapabilityGenerationMismatch,
                GraphGenerationMismatch,
                assert_capability_generation,
                assert_graph_generation,
                capability_gen_id,
                graph_gen_id,
            )
        except Exception:
            logger.debug("GraphGenID imports skipped", exc_info=True)
        else:
            try:
                run_id = str(getattr(self._ctx, "run_id", "") or "")
                output_dir = getattr(self._config, "output_dir", None)
                if run_id and output_dir:
                    snap = DagCheckpointStore(
                        Path(str(output_dir)) / run_id / "dag_checkpoint.json"
                    ).load()
                    if snap is not None:
                        if snap.graph_gen_id:
                            assert_graph_generation(snap.graph_gen_id, graph_gen_id(self._graph))
                        if snap.capability_gen_id:
                            assert_capability_generation(
                                snap.capability_gen_id, capability_gen_id(self._graph)
                            )
            except (GraphGenerationMismatch, CapabilityGenerationMismatch) as exc:
                logger.error("GraphGenID/capability resume mismatch: %s", exc)
                self._outcome.exit_code = EXIT_INFRA_FAILURE
                return self._outcome
            except Exception:
                logger.debug("GraphGenID resume check skipped", exc_info=True)

        # Seed StagePlanner with learning integration
        from src.pipeline.services.pipeline_orchestrator.stage_planner import StagePlanner

        planner = StagePlanner(
            self._config,
            self._ctx,
            self._orchestrator.observability_bus.learning_integration,
            graph=self._graph,
        )

        # Capture initial config keys before starting the readiness loop
        initial_config_keys = {k for k in dir(self._config) if not k.startswith("_")}
        overridden_keys: set[str] = set()

        while True:
            if self._failed_critical is not None and self._abort_pipeline_on_critical():
                if self._outcome.exit_code is None:
                    self._outcome.exit_code = EXIT_INFRA_FAILURE
                break
            if self._deadline_exceeded():
                logger.warning("ActorScheduler: global max-duration exceeded; stopping dispatch")
                if self._outcome.exit_code is None:
                    self._outcome.exit_code = EXIT_PARTIAL
                self._skip_remaining_for_deadline()
                break
            if self._shutdown_requested():
                logger.warning("Shutdown flag detected by ActorScheduler, stopping.")
                self._outcome.exit_code = EXIT_INTERRUPTED
                break

            # Dynamically plan remaining stages and calibrate resources/timeouts
            previous_remaining = set(self._remaining)
            planned_remaining, resources = planner.plan_stages(list(self._remaining))
            planned_set = set(planned_remaining)
            for name in previous_remaining - planned_set:
                reason = self._planner_skip_reason(name)
                self._mark_skipped_by_name(name, reason=reason)
            for name in planned_set - previous_remaining:
                self._injected.add(name)
                self._progress_emitter(
                    name,
                    "Planner injected stage",
                    0,
                    status="pending",
                    stage_status="pending",
                    injected=True,
                    event_trigger="stage_injected",
                )
            self._remaining = planned_set
            if resources:
                # Merge dynamically planned stage timeouts or other adjustments
                for k, v in resources.items():
                    if k.endswith("_stage_timeout_seconds"):
                        stage_name = k.replace("_stage_timeout_seconds", "")
                        config_key = f"{stage_name}_stage_timeout_seconds"
                    else:
                        config_key = k

                    if config_key in initial_config_keys and config_key not in overridden_keys:
                        # User-configured originally, do not overwrite!
                        continue
                    if config_key not in overridden_keys:
                        setattr(self._config, config_key, v)
                        overridden_keys.add(config_key)

            ready = self._collect_ready_nodes()
            if ready:
                try:
                    from src.infrastructure.resource_guard import ResourceGuard

                    # Bug #19: Check OOM before dispatching the batch, not just
                    # once for the whole loop. This prevents burst scheduling
                    # from overwhelming memory.
                    guard = ResourceGuard()
                    error_detail = guard.check_and_halt_on_oom()
                    if error_detail:
                        logger.error("System resource check failed: %s", error_detail)
                        self._error_emitter(
                            "resource_guard", f"Critical OOM detected: {error_detail}"
                        )
                        self._outcome.exit_code = EXIT_PARTIAL
                        self._skip_remaining_keep_sinks(reason="resource_pressure")
                        try:
                            from src.pipeline.mvr import emit_bound_partial_report

                            emit_bound_partial_report("resource_guard_critical")
                        except Exception:
                            logger.debug(
                                "partial report on resource pressure skipped", exc_info=True
                            )
                        break
                    try:
                        from src.core.runtime.resource_guard import PressureLevel, inspect_pressure

                        _snap, level, _pct = inspect_pressure()
                        if level is PressureLevel.CRITICAL:
                            logger.error("ResourceGuard CRITICAL disk/mem; graceful finalize")
                            self._outcome.exit_code = 4
                            self._skip_remaining_keep_sinks(reason="resource_guard_critical")
                            from src.pipeline.mvr import emit_bound_partial_report

                            emit_bound_partial_report("resource_guard_critical")
                            break
                    except Exception:
                        logger.debug("inspect_pressure skipped", exc_info=True)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("ResourceGuard early check failed (%s).", exc)

                # Bug #25: Use unified CapacityManager for all dispatch decisions.
                try:
                    from src.core.capacity_manager import get_capacity_manager

                    capacity_mgr = get_capacity_manager()
                except ImportError:
                    capacity_mgr = None

                for node in ready:
                    if capacity_mgr is not None:
                        # Estimate RAM for this task and check unified capacity
                        try:
                            from src.infrastructure.resource_guard import ResourceGuard

                            task_ram = ResourceGuard().estimate_stage_ram(
                                node.name,
                                target_count=len(self._graph.nodes),
                                url_count=0,
                            )
                        except Exception:
                            task_ram = 0

                        ok, deny_reason = capacity_mgr.can_dispatch(
                            subsystem="actor_scheduler",
                            estimated_ram_mb=task_ram,
                            stage_name=node.name,
                        )
                        if not ok:
                            logger.debug(
                                "CapacityManager denied dispatch for '%s': %s",
                                node.name,
                                deny_reason,
                            )
                            continue
                    else:
                        # Fallback: legacy ConcurrencyGovernor check
                        try:
                            from src.core.concurrency_governor import get_governor

                            governor = get_governor()
                            if not governor.allow("actor_scheduler"):
                                logger.debug(
                                    "Concurrency governor denied dispatch for '%s' — deferring",
                                    node.name,
                                )
                                continue
                        except ImportError:
                            pass

                    self._dispatch(node)
            if self._in_flight:
                await self._await_any_completion()
                continue

            if not self._in_flight:
                # Defensive re-check: a node may have become ready while we
                # were awaiting the previous batch (e.g. a dependency
                # completed and its ``when`` predicate is now satisfied).
                # Only break when there are truly no ready nodes left.
                ready = self._collect_ready_nodes()
                if ready:
                    for node in ready:
                        self._dispatch(node)
                    if self._in_flight:
                        await self._await_any_completion()
                        continue
                break
            await self._await_any_completion()

        self._apply_re_scheduling()

        re_sched_tasks = [st.task for st in self._in_flight.values()]
        if re_sched_tasks:
            logger.info("ActorScheduler: awaiting %d re-scheduled tasks", len(re_sched_tasks))
            await asyncio.wait(re_sched_tasks, return_when=asyncio.ALL_COMPLETED)

        self._finalize_unsatisfiable_nodes()

        logger.info(
            "ActorScheduler: done. completed=%d skipped=%d failed=%d speculative=%d reschedules=%d",
            len(self._outcome.completed),
            len(self._outcome.skipped),
            len(self._outcome.failed),
            len(self._outcome.speculative_dispatches),
            len(self._outcome.re_schedules),
        )
        return self._outcome

    # ------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------

    def _collect_ready_nodes(self) -> list[StageNode]:
        """Return the set of nodes ready to dispatch, sorted by weight.

        Sort order is ``weight`` descending, then declaration order.
        This means the longest expected stage on the critical path
        gets the worker pool first when multiple stages unblock
        simultaneously — the classic critical-path heuristic.

        Nodes that have been deferred more than ``_max_deferrals`` times
        are forced through regardless of debt status to prevent starvation.
        """
        ready: list[tuple[int, int, StageNode]] = []
        for index, node in enumerate(self._graph.nodes):
            if node.name in self._completed or node.name in self._skipped:
                continue
            if node.name in self._launched:
                continue
            if node.name not in self._remaining:
                continue
            if not self._deps_satisfied(node):
                continue
            if not self._condition_holds(node):
                # P_DEF (DEFERRED): dependencies met, waiting on dynamic when condition
                self._deferred.add(node.name)
                count = self._deferral_counts.get(node.name, 0) + 1
                self._deferral_counts[node.name] = count
                if count >= self._max_deferrals and not self._in_flight:
                    # Starvation guard: if no other stages in-flight can satisfy condition
                    logger.info(
                        "ActorScheduler: stage '%s' exceeded max deferrals (%d); marking skipped",
                        node.name,
                        self._max_deferrals,
                    )
                    self._mark_skipped(node, reason="condition_never_satisfied")
                    self._deferred.discard(node.name)
                continue
            self._deferred.discard(node.name)
            if self._is_large_debt_node(node):
                continue
            ready.append((node.weight * -1, index, node))

        ready.sort(key=lambda triple: (triple[0], triple[1]))
        if ready:
            ready_names = [node.name for _w, _i, node in ready]
            # Deduplicate: don't append if the last entry already has the same ready set
            last_entry = (
                self._outcome.speculative_dispatches[-1]
                if self._outcome.speculative_dispatches
                else None
            )
            if last_entry is None or last_entry.get("ready") != ready_names:
                self._outcome.speculative_dispatches.append(
                    {
                        "reason": REASON_SPECULATIVE_DISPATCH,
                        "ready": ready_names,
                        "timestamp": _utcnow_iso(),
                    }
                )
            logger.debug(
                "ActorScheduler: speculative dispatch ready=%s",
                [node.name for _w, _i, node in ready],
            )
        return [node for _w, _i, node in ready]

    _JOIN_SINKS = frozenset(
        {"reporting", "intelligence", "sarif_export", "ci_export", "dedup_stage"}
    )

    def _deps_satisfied(self, node: StageNode) -> bool:
        return all(self._need_met(dep, node) for dep in node.needs)

    def _need_met(self, dep: str, node: StageNode) -> bool:
        """CAS-aware join.

        Reporting/intel wait until every producer is *terminal* (including
        FAILED, so the report still emits). FAILED never counts as success
        for OutputNonEmpty gates (those use StageCompleted/OutputNonEmpty).
        """
        from src.core.models.stage_status import (
            TERMINAL_STAGE_STATUSES,
            StageStatus,
            normalize_stage_status,
        )

        raw = None
        try:
            raw = self._ctx.result.stage_status.get(dep)
        except Exception:
            raw = None
        status = normalize_stage_status(raw) if raw is not None else None
        if node.name in self._JOIN_SINKS:
            if status in TERMINAL_STAGE_STATUSES:
                return True
            return (
                dep in self._completed
                or dep in self._skipped
                or dep in self._outcome.skipped
                or dep in self._outcome.failed
            )
        if status in {StageStatus.COMPLETED, StageStatus.DEGRADED}:
            return True
        # P0 review: SKIPPED_DISABLED must not silently satisfy hard needs.
        # Only optional_needs (or scheduler-internal skip bookkeeping for the
        # same node being optional) may treat disabled upstream as met.
        optional = set(getattr(node, "optional_needs", ()) or ())
        if status is StageStatus.SKIPPED_DISABLED:
            return dep in optional
        if dep in self._skipped or dep in self._outcome.skipped:
            # Internal skip set: allow only when marked optional or previously
            # completed path already recorded.
            return dep in optional or dep in self._completed
        if dep in self._completed:
            return True
        return False

    def _condition_holds(self, node: StageNode) -> bool:
        try:
            result = bool(node.when.is_satisfied(self._ctx, self._runtime_flags))
            return result
        except Exception as exc:  # noqa: BLE001 — broad catch intentional, condition predicates may raise arbitrary errors
            # A condition predicate that raises is almost certainly a bug,
            # not a legitimate "condition not met".  Log at error level so
            # it surfaces in diagnostics, and treat the node as deferred
            # (not skipped) so it is retried on the next tick.
            logger.error(
                "BUG: Condition evaluation raised for stage '%s' (%s); "
                "treating as deferred — this is NOT a normal skip",
                node.name,
                exc,
                exc_info=True,
            )
            return False

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, node: StageNode) -> None:
        if node.name in self._launched:
            return
        if node.name in self._completed:
            return
        admission_gen = int(getattr(self, "_admission_gen", 0))
        try:
            from src.core.runtime.resource_guard import PressureLevel, inspect_pressure

            _snap, level, _pct = inspect_pressure()
            if level is PressureLevel.CRITICAL:
                self._mark_skipped(node, reason="resource_guard_critical")
                return
        except Exception:
            logger.debug("ResourceGuard admission probe skipped", exc_info=True)
        if admission_gen != int(getattr(self, "_admission_gen", 0)):
            self._mark_skipped(node, reason="resource_pressure")
            return
        self._launched.add(node.name)
        try:
            self._progress_emitter(
                node.name,
                f"Stage ready: {node.name}",
                0,
                status="ready",
                stage_status="ready",
                event_trigger="stage_ready",
                injected=node.name in self._injected,
            )
        except Exception:
            logger.debug("Failed to emit ready progress for %s", node.name, exc_info=True)

        method = self._stage_methods.get(node.name)
        if method is None:
            logger.error(
                "Stage method resolution failed for stage '%s'. Marking skipped.",
                node.name,
            )
            self._error_emitter(
                node.name,
                "Stage method resolution failed: stage method not found.",
            )
            self._mark_skipped(node, reason="method_not_found")
            self._release_capacity(node.name)
            return

        if not self._suspend_ok(node):
            self._mark_skipped(node, reason="suspend_triggered")
            self._release_capacity(node.name)
            return

        import time as _time

        from src.core.task_registry import get_task_registry

        task = get_task_registry().create_task(
            self._execute_node(node, method),
            owner="actor_scheduler",
            name=f"actor.{node.name}",
        )
        self._in_flight[task] = _ScheduledTask(node=node, task=task, started_at=_time.time())
        logger.debug(
            "Dispatched actor for stage '%s' (weight=%d, reason=%s)",
            node.name,
            node.weight,
            REASON_PRIORITY if node.weight > 1 else REASON_SPECULATIVE_DISPATCH,
        )

    def _release_capacity(self, stage_name: str) -> None:
        """Release capacity slot if one was acquired but no task was created.

        Defect 3 fix: When _dispatch() returns early (method not found,
        suspend triggered), the capacity slot acquired by can_dispatch()
        must be released to prevent permanent capacity leaks.
        """
        try:
            from src.core.capacity_manager import get_capacity_manager

            capacity_mgr = get_capacity_manager()
            capacity_mgr.release("actor_scheduler")
        except (ImportError, Exception):
            try:
                from src.core.concurrency_governor import get_governor

                get_governor().release("actor_scheduler")
            except (ImportError, Exception):
                pass

    async def _execute_node(
        self,
        node: StageNode,
        method: Callable[..., Awaitable[Any]],
    ) -> Any:
        return await self._orchestrator._execute_single_stage(
            node.name,
            method,
            self._args,
            self._config,
            self._ctx,
            self._scope_interceptor,
            self._checkpoint_mgr,
            self._stage_checkpoint_guard,
            self._progress_emitter,
            self._error_emitter,
            critical=node.critical,
        )

    # ------------------------------------------------------------------
    # Await
    # ------------------------------------------------------------------

    async def _await_any_completion(self) -> None:
        if not self._in_flight:
            return
        tasks = list(self._in_flight.keys())
        done, _pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        # Bug #25: Release via unified CapacityManager instead of ConcurrencyGovernor
        try:
            from src.core.capacity_manager import get_capacity_manager

            capacity_mgr = get_capacity_manager()
        except ImportError:
            capacity_mgr = None

        for task in done:
            scheduled = self._in_flight.pop(task, None)
            if scheduled is None:
                continue
            if capacity_mgr is not None:
                capacity_mgr.release("actor_scheduler")
            else:
                # Bug #10: Legacy fallback — release governor slot directly
                # when CapacityManager is unavailable.  Without this,
                # every dispatch in the legacy path leaks one governor
                # slot permanently, eventually exhausting the global limit.
                try:
                    from src.core.concurrency_governor import get_governor

                    get_governor().release("actor_scheduler")
                except (ImportError, Exception):
                    pass
            try:
                result = task.result()
            except asyncio.CancelledError:
                logger.warning("Stage '%s' was cancelled", scheduled.node.name)
                self._mark_skipped(scheduled.node, reason="cancelled")
                continue
            except BaseException as exc:  # noqa: BLE001 — broad catch intentional, must not let stage exceptions escape actor loop
                logger.exception(
                    "Stage '%s' raised in actor scheduler: %s",
                    scheduled.node.name,
                    exc,
                )
                self._handle_fatal(scheduled.node, exc)
                continue

            self._handle_completion(scheduled.node, result)
            self._record_re_schedule_decision(scheduled.node)

    # ------------------------------------------------------------------
    # Completion handling
    # ------------------------------------------------------------------

    def _handle_completion(self, node: StageNode, result: Any) -> None:
        status = self._ctx.result.stage_status.get(node.name)
        if status == StageStatus.FAILED.value:
            self._record_stage_failure(node, error="stage_failed")
            return
        if status == StageStatus.DEGRADED.value:
            self._completed.add(node.name)
            self._outcome.completed.add(node.name)
            self._run_post_completion_hook(node)
            self._record_speculative_completion(node)
            return

        self._completed.add(node.name)
        self._outcome.completed.add(node.name)
        self._run_post_completion_hook(node)
        self._record_speculative_completion(node)

    def _handle_fatal(self, node: StageNode, exc: BaseException) -> None:
        self._ctx.result.stage_status[node.name] = StageStatus.FAILED.value
        self._ctx.result.module_metrics[node.name] = {
            "status": "error",
            "error": str(exc) or exc.__class__.__name__,
            "failure_reason": str(exc) or exc.__class__.__name__,
            "fatal": node.critical,
        }
        self._record_stage_failure(node, error=str(exc) or exc.__class__.__name__)
        self._error_emitter(
            node.name,
            f"Stage '{node.name}' raised: {exc}",
        )

    def _abort_pipeline_on_critical(self) -> bool:
        from src.pipeline.mvr import continue_on_non_critical, strict_critical

        if not continue_on_non_critical():
            return True
        return strict_critical()

    def _record_stage_failure(self, node: StageNode, *, error: str) -> None:
        from src.pipeline.mvr import abort_on_stage_failure

        if abort_on_stage_failure(node):
            self._outcome.failed.add(node.name)
            if node.critical or node.must_succeed:
                self._failed_critical = node.name
                self._error_emitter(
                    node.name,
                    f"must_succeed stage '{node.name}' failed ({error}); "
                    "skipping dependents, continuing independent work.",
                )
            self._cascade_unsatisfiable()
            return
        logger.warning(
            "Stage '%s' failed -> DEGRADED (continuing) error=%s",
            node.name,
            error,
        )
        try:
            self._ctx.result.stage_status[node.name] = StageStatus.DEGRADED.value
        except Exception:
            logger.debug("Unable to coerce %s to DEGRADED", node.name, exc_info=True)
        metrics = {}
        try:
            metrics = dict(self._ctx.result.module_metrics.get(node.name) or {})
        except Exception:
            metrics = {}
        metrics.update(
            {
                "status": "degraded",
                "degraded_from": "failed",
                "error": error,
                "error_summary": error[:8192],
            }
        )
        self._ctx.result.module_metrics[node.name] = metrics
        self._completed.add(node.name)
        self._outcome.completed.add(node.name)

    def _cascade_unsatisfiable(self) -> None:
        """Mark dependents of a just-failed critical stage so join sinks unblock."""
        self._finalize_unsatisfiable_nodes()
        self._persist_dag_checkpoint()

    def _persist_dag_checkpoint(self, current_stage: str = "") -> None:
        try:
            from pathlib import Path

            from src.core.checkpoint.dag_checkpoint import DagCheckpoint, DagCheckpointStore

            run_id = str(getattr(self._ctx, "run_id", "") or "")
            if not run_id:
                return
            output_dir = getattr(self._config, "output_dir", None)
            if not output_dir:
                return
            stage_status: dict[str, str] = {}
            try:
                stage_status = {
                    str(k): str(v) for k, v in dict(self._ctx.result.stage_status).items()
                }
            except Exception:
                stage_status = {}
            gen = ""
            try:
                from src.pipeline.graph_identity import capability_gen_id, graph_gen_id

                gen = graph_gen_id(self._graph)
                cap = capability_gen_id(self._graph)
            except Exception:
                gen = ""
                cap = ""
            tickets: list[str] = []
            try:
                runtime = getattr(self._ctx, "authority_runtime", None)
                authorizer = getattr(runtime, "authorizer", None) or getattr(
                    self._ctx, "execution_authorizer", None
                )
                getter = getattr(authorizer, "consumed_ticket_ids", None)
                if callable(getter):
                    tickets = sorted(str(x) for x in getter() if x)
            except Exception:
                tickets = []
            snap = DagCheckpoint(
                run_id=run_id,
                status="RUNNING",
                stage_status=stage_status,
                completed=sorted(self._completed),
                failed=sorted(self._outcome.failed),
                current_stage=current_stage,
                graph_gen_id=gen,
                capability_gen_id=cap,
                consumed_ticket_ids=tickets,
            )
            DagCheckpointStore(Path(str(output_dir)) / run_id / "dag_checkpoint.json").save(snap)
        except Exception:
            logger.debug("dag checkpoint persist skipped", exc_info=True)

    def _record_speculative_completion(self, node: StageNode) -> None:
        for entry in reversed(self._outcome.speculative_dispatches):
            if node.name in entry.get("ready", []):
                entry.setdefault("completed", []).append(node.name)
                break

    # ------------------------------------------------------------------
    # Re-scheduling (dynamic tier rebalancing)
    # ------------------------------------------------------------------

    def _apply_re_scheduling(self) -> None:
        # Bug fix: Guard against re-dispatching after the scheduler has
        # decided to exit due to a critical failure. Without this check,
        # late-unblocked nodes can be re-dispatched after the main loop
        # has already given up, running stages out of intended order.
        if self._failed_critical is not None and self._abort_pipeline_on_critical():
            logger.debug(
                "ActorScheduler: skipping re-scheduling (failed_critical=%s)",
                self._failed_critical,
            )
            return
        for node in self._graph.nodes:
            if node.name in self._completed or node.name not in self._remaining:
                continue
            if (
                self._deps_satisfied(node)
                and self._condition_holds(node)
                and not self._is_large_debt_node(node)
            ):
                self._dispatch(node)

    def _record_re_schedule_decision(self, node: StageNode) -> None:
        if not _is_large_output(node.name, self._config, self._ctx):
            return
        rebalanced = self._suggest_rebalance(node)
        if not rebalanced:
            return
        self._outcome.re_schedules.append(
            {
                "reason": REASON_RE_SCHEDULE,
                "source": node.name,
                "rebalanced": sorted(rebalanced),
                "timestamp": _utcnow_iso(),
            }
        )
        logger.info(
            "ActorScheduler: re-schedule after %s completion; rebalancing %s",
            node.name,
            sorted(rebalanced),
        )

    def _suggest_rebalance(self, node: StageNode) -> set[str]:
        if not _is_large_output(node.name, self._config, self._ctx):
            return set()
        threshold = self._effective_rebalance_threshold()
        rebalanced = _downstream_for_rebalance(node, self._graph)
        if not rebalanced:
            return set()
        if len(rebalanced) < threshold:
            return set()
        return set(rebalanced)

    def _effective_rebalance_threshold(self) -> int:
        try:
            factor = getattr(self._config, "rebalance_group_factor", None)
            if isinstance(factor, int) and factor > 0:
                return factor
        except (AttributeError, TypeError) as exc:  # noqa: BLE001 — broad catch intentional, config may be any type
            logger.debug("Failed to read rebalance_group_factor from config: %s", exc)
        return DEFAULT_REBALANCE_THRESHOLD_FACTOR

    def _is_large_debt_node(self, node: StageNode) -> bool:
        """Advisory rebalance only. Never starve a join sink.

        Counting ``needs not in _completed`` treated FAILED nuclei as
        unpaid debt and blocked reporting forever. Join waits for
        *terminal* producers via ``_need_met``.
        """
        if node.name in self._JOIN_SINKS:
            return False
        threshold = self._effective_rebalance_threshold()
        count = sum(1 for dep in node.needs if not self._need_met(dep, node))
        return count >= threshold

    # ------------------------------------------------------------------
    # Post-completion hooks
    # ------------------------------------------------------------------

    def _run_post_completion_hook(self, node: StageNode) -> None:
        hook = self._post_completion_hooks.get(node.name)
        if hook is None:
            return
        try:
            hook(self._ctx)
        except Exception as exc:  # noqa: BLE001 — broad catch intentional, hook may raise arbitrary errors
            logger.warning(
                "Post-completion hook for '%s' raised: %s",
                node.name,
                exc,
            )

    # ------------------------------------------------------------------
    # Finalisation
    # ------------------------------------------------------------------

    def _finalize_unsatisfiable_nodes(self) -> None:
        """Mark nodes that never became ready as SKIPPED.

        Covers permanently-false ``when`` predicates and dependents of a
        FAILED critical stage that will never be re-evaluated after the
        loop exits.
        """
        for node in self._graph.nodes:
            if node.name in self._completed:
                continue
            if node.name in self._launched:
                continue
            if node.name in self._outcome.skipped:
                continue
            if node.name not in self._remaining:
                continue
            if any(
                dep in self._outcome.failed and self._graph.require(dep).critical
                for dep in node.needs
            ):
                self._mark_skipped(node, reason="upstream_critical_failure")
                continue
            if not self._condition_holds(node):
                self._mark_skipped(node, reason="condition_never_satisfied")

    def _planner_skip_reason(self, name: str) -> str:
        metrics: dict[str, Any] = {}
        try:
            metrics = self._ctx.result.module_metrics.get(name, {}) or {}
        except Exception:
            metrics = {}
        if isinstance(metrics, dict):
            reason = str(metrics.get("reason") or "").strip()
            if reason:
                return reason
        return "planner_dropped"

    def _mark_skipped_by_name(self, name: str, *, reason: str) -> None:
        for node in self._graph.nodes:
            if node.name == name:
                self._mark_skipped(node, reason=reason)
                return
        self._skipped.add(name)
        self._outcome.skipped.add(name)
        try:
            self._ctx.result.stage_status[name] = StageStatus.SKIPPED.value
            self._ctx.result.module_metrics[name] = {
                "status": "skipped",
                "reason": reason,
            }
        except Exception:
            logger.debug("Failed to record planner skip for %s", name, exc_info=True)
        logger.info("Stage '%s' skipped: %s", name, reason)
        try:
            emit_stage_skipped(name, reason)
        except Exception:
            logger.debug("Failed to emit skip progress for %s", name, exc_info=True)

    def _mark_skipped(self, node: StageNode, *, reason: str) -> None:
        from src.core.models.stage_status import resolve_skip_status

        self._skipped.add(node.name)
        self._outcome.skipped.add(node.name)
        dest = resolve_skip_status(reason)
        self._ctx.result.stage_status[node.name] = dest.value
        self._ctx.result.module_metrics[node.name] = {
            "status": dest.value.lower(),
            "reason": reason,
        }
        logger.info("Stage '%s' skipped: %s", node.name, reason)
        try:
            emit_stage_skipped(node.name, reason)
        except Exception:
            logger.debug("Failed to emit skip progress for %s", node.name, exc_info=True)

    # ------------------------------------------------------------------
    # Cancellation / shutdown helpers
    # ------------------------------------------------------------------

    def _deadline_exceeded(self) -> bool:
        if self._max_duration_seconds is None:
            return False
        return (time.monotonic() - self._run_started_at) >= self._max_duration_seconds

    def _skip_remaining_for_deadline(self) -> None:
        self._skip_remaining_keep_sinks(reason="global_deadline_exceeded")

    def _skip_remaining_keep_sinks(self, *, reason: str) -> None:
        """Stop new work but keep reporting/sarif/ci_export dispatchable.

        Force-terminal any non-sink that is not already terminal, including
        PENDING stages that were never launched, so join sinks cannot deadlock
        waiting on a producer stuck in PENDING under ResourceGuard CRITICAL.
        """
        from src.core.models.stage_status import (
            TERMINAL_STAGE_STATUSES,
            normalize_stage_status,
        )

        self._admission_gen = int(getattr(self, "_admission_gen", 0)) + 1
        keep = set(self._JOIN_SINKS)
        for node in self._graph.nodes:
            if node.name in keep:
                continue
            if node.name in self._launched:
                continue
            raw = None
            try:
                raw = self._ctx.result.stage_status.get(node.name)
            except Exception:
                raw = None
            status = normalize_stage_status(raw) if raw is not None else None
            if status in TERMINAL_STAGE_STATUSES:
                continue
            if (
                node.name in self._completed
                or node.name in self._skipped
                or node.name in self._outcome.skipped
            ):
                continue
            self._mark_skipped(node, reason=reason)

    def _shutdown_requested(self) -> bool:
        try:
            from src.pipeline.runtime import _is_shutdown_requested

            return _is_shutdown_requested()
        except ImportError:
            return False

    def _suspend_ok(self, node: StageNode) -> bool:
        """Honor the HotReload suspend trigger between dispatches."""
        try:
            from src.core.hot_reload import HotReloadManager

            reload_mgr = HotReloadManager(self._config.output_dir)
            target_name = str(getattr(self._config, "target_name", ""))
            if reload_mgr.check_suspend_trigger(target_name, node.name):
                logger.warning(
                    "Pipeline paused cleanly via suspend trigger at stage '%s'.",
                    node.name,
                )
                self._outcome.exit_code = EXIT_SUSPEND
                self._failed_critical = node.name
                return False
        except Exception as exc:  # noqa: BLE001 — broad catch intentional, suspend check must not crash scheduler
            logger.debug("Suspend check failed for '%s': %s", node.name, exc)
        return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _utcnow_iso() -> str:
    import datetime

    return datetime.datetime.now(datetime.UTC).isoformat()
