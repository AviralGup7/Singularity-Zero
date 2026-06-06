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
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import StageStatus

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
    except Exception:  # noqa: BLE001
        pass
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
    except Exception:  # noqa: BLE001
        return False
    try:
        if hasattr(value, "__len__"):
            return len(value) >= threshold
    except TypeError:
        pass
    return False


def _downstream_for_rebalance(node: StageNode, graph: Graph) -> frozenset[str]:
    result: set[str] = set()
    queue: list[str] = list(node.needs)
    visited: set[str] = set()
    while queue:
        current = queue.pop()
        if current in visited:
            continue
        visited.add(current)
        candidate = graph.get(current)
        if candidate is not None:
            result.update(candidate.needs)
            queue.extend(candidate.needs)
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
        self._skipped: set[str] = set()
        self._failed_critical: str | None = None
        self._outcome = SchedulerOutcome()

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

        # Seed StagePlanner with learning integration
        from src.pipeline.services.pipeline_orchestrator.stage_planner import StagePlanner
        planner = StagePlanner(self._config, self._ctx, self._orchestrator.observability_bus.learning_integration)

        while True:
            if self._failed_critical is not None:
                break
            if self._shutdown_requested():
                logger.warning("Shutdown flag detected by ActorScheduler, stopping.")
                self._outcome.exit_code = 130
                break

            # Dynamically plan remaining stages and calibrate resources/timeouts
            planned_remaining, resources = planner.plan_stages(list(self._remaining))
            self._remaining = set(planned_remaining)
            if resources:
                # Merge dynamically planned stage timeouts or other adjustments
                for k, v in resources.items():
                    if k.endswith("_stage_timeout_seconds"):
                        stage_name = k.replace("_stage_timeout_seconds", "")
                        # Save/override timeout settings in config or runtime state
                        setattr(self._config, f"{stage_name}_stage_timeout_seconds", v)
                    else:
                        setattr(self._config, k, v)

            ready = self._collect_ready_nodes()
            if ready:
                from src.pipeline.validation import probe_system_resources
                is_healthy, details = probe_system_resources(getattr(self._config, "output_dir", "."))
                if not is_healthy:
                    logger.error("System resource check failed: %s", details)
                    self._error_emitter("resource_probe", f"Insufficient system resources: {details}")
                    self._failed_critical = "resource_probe"
                    self._outcome.exit_code = 1
                    break
                for node in ready:
                    self._dispatch(node)
                if self._in_flight:
                    await self._await_any_completion()
                continue

            if not self._in_flight:
                break
            await self._await_any_completion()

        self._apply_re_scheduling()

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
                continue
            ready.append((node.weight * -1, index, node))

        ready.sort(key=lambda triple: (triple[0], triple[1]))
        if ready:
            self._outcome.speculative_dispatches.append(
                {
                    "reason": REASON_SPECULATIVE_DISPATCH,
                    "ready": [node.name for _w, _i, node in ready],
                    "timestamp": _utcnow_iso(),
                }
            )
            logger.debug(
                "ActorScheduler: speculative dispatch ready=%s",
                [node.name for _w, _i, node in ready],
            )
        return [node for _w, _i, node in ready]

    def _deps_satisfied(self, node: StageNode) -> bool:
        return all(dep in self._completed or dep in self._skipped or dep in self._outcome.skipped for dep in node.needs)


    def _condition_holds(self, node: StageNode) -> bool:
        try:
            return bool(node.when.is_satisfied(self._ctx, self._runtime_flags))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Condition evaluation failed for stage '%s' (%s); treating as deferred",
                node.name,
                exc,
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
        self._launched.add(node.name)

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
            return

        if not self._suspend_ok(node):
            self._mark_skipped(node, reason="suspend_triggered")
            return

        import time as _time

        task = asyncio.create_task(
            self._execute_node(node, method),
            name=f"actor.{node.name}",
        )
        self._in_flight[task] = _ScheduledTask(node=node, task=task, started_at=_time.time())
        logger.debug(
            "Dispatched actor for stage '%s' (weight=%d, reason=%s)",
            node.name,
            node.weight,
            REASON_PRIORITY if node.weight > 1 else REASON_SPECULATIVE_DISPATCH,
        )

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
        )

    # ------------------------------------------------------------------
    # Await
    # ------------------------------------------------------------------

    async def _await_any_completion(self) -> None:
        if not self._in_flight:
            return
        tasks = list(self._in_flight.keys())
        done, _pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
        for task in done:
            scheduled = self._in_flight.pop(task, None)
            if scheduled is None:
                continue
            try:
                result = task.result()
            except asyncio.CancelledError:
                logger.warning("Stage '%s' was cancelled", scheduled.node.name)
                self._mark_skipped(scheduled.node, reason="cancelled")
                continue
            except BaseException as exc:  # noqa: BLE001
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
            self._outcome.failed.add(node.name)
            if node.critical:
                self._failed_critical = node.name
                self._error_emitter(
                    node.name,
                    f"Critical stage '{node.name}' failed; aborting pipeline.",
                )
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
        self._outcome.failed.add(node.name)
        if node.critical:
            self._failed_critical = node.name
        self._error_emitter(
            node.name,
            f"Stage '{node.name}' raised: {exc}",
        )

    def _record_speculative_completion(self, node: StageNode) -> None:
        for entry in reversed(self._outcome.speculative_dispatches):
            if node.name in entry.get("ready", []):
                entry.setdefault("completed", []).append(node.name)
                break

    # ------------------------------------------------------------------
    # Re-scheduling (dynamic tier rebalancing)
    # ------------------------------------------------------------------

    def _apply_re_scheduling(self) -> None:
        for node in self._graph.nodes:
            if node.name in self._completed or node.name not in self._remaining:
                continue
            if self._deps_satisfied(node) and self._condition_holds(node) and not self._is_large_debt_node(node):
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
        except Exception:  # noqa: BLE001
            pass
        return DEFAULT_REBALANCE_THRESHOLD_FACTOR

    def _is_large_debt_node(self, node: StageNode) -> bool:
        threshold = self._effective_rebalance_threshold()
        count = sum(1 for dep in node.needs if dep not in self._completed)
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
        except Exception as exc:  # noqa: BLE001
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

        This covers two cases:

        * A node's ``when`` predicate is permanently false (e.g. the
          upstream stage produced an empty output and the node opted
          in to skip-on-empty).
        * A node's ``needs`` include a FAILED critical stage — the
          condition will never be re-evaluated after the loop
          exits, so we mark it now for reporting.
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

    def _mark_skipped(self, node: StageNode, *, reason: str) -> None:
        self._skipped.add(node.name)
        self._outcome.skipped.add(node.name)
        self._ctx.result.stage_status[node.name] = StageStatus.SKIPPED.value
        self._ctx.result.module_metrics[node.name] = {
            "status": "skipped",
            "reason": reason,
        }
        logger.info("Stage '%s' skipped: %s", node.name, reason)

    # ------------------------------------------------------------------
    # Cancellation / shutdown helpers
    # ------------------------------------------------------------------

    def _shutdown_requested(self) -> bool:
        try:
            from src.pipeline.runtime import shutdown_flag

            if hasattr(shutdown_flag, "is_set"):
                return bool(shutdown_flag.is_set())
            return bool(shutdown_flag)
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
                self._outcome.exit_code = 7
                self._failed_critical = node.name
                return False
        except Exception as exc:  # noqa: BLE001
            logger.debug("Suspend check failed for '%s': %s", node.name, exc)
        return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _utcnow_iso() -> str:
    import datetime

    return datetime.datetime.now(datetime.UTC).isoformat()
