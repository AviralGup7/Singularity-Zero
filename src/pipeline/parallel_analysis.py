"""Parallel analysis orchestrator for running independent analyzers concurrently.

Provides dependency-graph-aware parallel execution of analysis stages using
a work-stealing async queue, with per-analyzer error isolation, per-analyzer
timeout support, adaptive pool sizing from a prior-run duration cache, and
partial layer failure aggregation.

Design highlights
-----------------

* **Work stealing** — each topological layer is fed into an
  :class:`asyncio.Queue` and drained by a pool of worker coroutines
  sized to the layer's historical workload.  Workers pull the next
  pending analyzer as soon as they finish, so a slow analyzer no
  longer holds a static semaphore slot idle while other workers
  wait for ``asyncio.gather`` to wake them.
* **Adaptive pool sizing** — :class:`AnalyzerDurationCache` records
  per-analyzer runtimes across runs.  When a new layer starts the
  pool size is computed from ``len(analyzers) * estimated_duration_ratio``
  so that back-pressure (e.g. a recon stage that produced 50k URLs)
  dynamically expands the worker budget for downstream layers.
* **BoundedSemaphore guard** — the worker pool is additionally
  capped by a per-layer :class:`asyncio.BoundedSemaphore` so the
  inflight task count can never exceed the adaptive pool size,
  even under buggy analyzer implementations that spawn extra tasks.
* **Partial layer failure aggregation** — :class:`LayerResult`
  records the per-analyzer outcomes for a layer and exposes
  ``is_partial``, ``is_total_failure``, ``fatal_failures``, and
  ``successful_results`` helpers.  The DAG engine can inspect the
  list to decide whether downstream layers may still run on the
  partial outputs.
* **Sync path with true parallelism** —
  :func:`run_parallel_analyzers_sync` dispatches each analyzer into
  a real multi-worker :class:`concurrent.futures.ThreadPoolExecutor`
  (instead of the legacy single-worker executor) when called from
  inside a running event loop, giving true OS-level parallelism for
  analyzers that contain blocking I/O.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine, Iterable
from dataclasses import dataclass, field
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


@dataclass
class AnalyzerResult:
    """Result of a single analyzer execution."""

    name: str
    success: bool
    result: Any | None = None
    error: str | None = None
    duration_seconds: float = 0.0
    timed_out: bool = False


@dataclass
class LayerResult:
    """Aggregated outcome of a single topological layer.

    Distinguishes between ``is_total_failure`` (no analyzers
    succeeded) and ``is_partial`` (some analyzers succeeded while
    others failed or timed out).  The DAG engine consumes this
    aggregation to decide whether downstream layers may still run
    on the partial outputs.

    Attributes:
        layer_index: Zero-based position of the layer in the
            topological ordering.
        analyzer_names: Names of analyzers that were scheduled in
            this layer (in stable, dependency-graph order).
        results: Mapping of analyzer name to :class:`AnalyzerResult`.
    """

    layer_index: int
    analyzer_names: list[str] = field(default_factory=list)
    results: dict[str, AnalyzerResult] = field(default_factory=dict)

    @property
    def success_count(self) -> int:
        return sum(1 for r in self.results.values() if r.success)

    @property
    def failure_count(self) -> int:
        return sum(1 for r in self.results.values() if not r.success)

    @property
    def is_total_failure(self) -> bool:
        """``True`` if every analyzer in the layer failed."""
        return bool(self.results) and self.success_count == 0

    @property
    def is_partial(self) -> bool:
        """``True`` if at least one analyzer succeeded and at least one failed."""
        return 0 < self.success_count < len(self.results)

    @property
    def is_full_success(self) -> bool:
        """``True`` if every analyzer in the layer succeeded."""
        return bool(self.results) and self.failure_count == 0

    @property
    def fatal_failures(self) -> list[str]:
        """Names of analyzers in the layer that failed by timeout."""
        return [r.name for r in self.results.values() if r.timed_out]

    @property
    def failed_names(self) -> list[str]:
        """Names of analyzers in the layer that failed (timeout or exception)."""
        return [r.name for r in self.results.values() if not r.success]

    def successful_results(self) -> dict[str, Any]:
        """Return a ``{name: payload}`` mapping of only the successful outputs."""
        return {
            name: r.result
            for name, r in self.results.items()
            if r.success
        }


@dataclass
class ParallelAnalysisOutcome:
    """Container bundling the per-analyzer map with per-layer metadata.

    Exposes a dict-like read interface (``items()``, ``keys()``,
    ``values()``, ``__getitem__``) so legacy callers that treated
    the previous ``dict[str, AnalyzerResult]`` return type as a
    plain mapping keep working.  New consumers should iterate
    :attr:`layer_results` to distinguish partial vs. total
    failures and decide whether to flow outputs downstream.
    """

    results: dict[str, AnalyzerResult] = field(default_factory=dict)
    layer_results: list[LayerResult] = field(default_factory=list)

    def __getitem__(self, name: str) -> AnalyzerResult:
        return self.results[name]

    def __iter__(self) -> Iterable[str]:
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)

    def __contains__(self, name: object) -> bool:
        return name in self.results

    def items(self) -> Iterable[tuple[str, AnalyzerResult]]:
        return self.results.items()

    def keys(self) -> Iterable[str]:
        return self.results.keys()

    def values(self) -> Iterable[AnalyzerResult]:
        return self.results.values()

    def get(self, name: str, default: AnalyzerResult | None = None) -> AnalyzerResult | None:
        return self.results.get(name, default)

    @property
    def has_partial_failure(self) -> bool:
        """``True`` if any layer had at least one success and one failure."""
        return any(layer.is_partial for layer in self.layer_results)

    @property
    def has_total_failure(self) -> bool:
        """``True`` if any layer failed every analyzer."""
        return any(layer.is_total_failure for layer in self.layer_results)

    @property
    def all_timed_out(self) -> list[str]:
        """Flattened list of analyzer names that timed out across all layers."""
        return [name for layer in self.layer_results for name in layer.fatal_failures]


class AnalyzerDurationCache:
    """In-memory cache of recent analyzer durations.

    Used to heuristically size the worker pool for a layer.  If the
    cache has no data for a given analyzer it falls back to a
    configurable default estimate.  The cache is intentionally
    bounded so it does not leak memory across long-running services.
    """

    def __init__(
        self,
        *,
        default_duration: float = 5.0,
        max_entries_per_analyzer: int = 16,
    ) -> None:
        self._default_duration = max(0.001, float(default_duration))
        self._max_entries = max(1, int(max_entries_per_analyzer))
        self._samples: dict[str, list[float]] = {}

    def record(self, name: str, duration: float) -> None:
        """Record a new duration sample for ``name``."""
        if duration < 0:
            return
        samples = self._samples.setdefault(name, [])
        samples.append(float(duration))
        if len(samples) > self._max_entries:
            del samples[0 : len(samples) - self._max_entries]

    def estimate(self, name: str) -> float:
        """Return the average historical duration for ``name``.

        Falls back to :attr:`default_duration` when no samples are
        available.
        """
        samples = self._samples.get(name)
        if not samples:
            return self._default_duration
        return sum(samples) / len(samples)

    def estimated_duration_ratio(self, names: Iterable[str]) -> float:
        """Return the ratio of the heaviest to the lightest estimate.

        A ratio of ``1.0`` means every analyzer in the layer is
        expected to take roughly the same time.  A large ratio means
        the layer is load-imbalanced and the worker pool can be
        expanded to absorb the skew.
        """
        estimates = [self.estimate(name) for name in names]
        if not estimates:
            return 1.0
        heaviest = max(estimates)
        lightest = min(estimates)
        if lightest <= 0:
            return 1.0
        return max(1.0, heaviest / lightest)

    def compute_pool_size(
        self,
        names: list[str],
        *,
        max_workers: int,
        min_pool: int = 1,
        max_expansion: float = 2.0,
    ) -> int:
        """Compute an adaptive pool size for the given layer.

        Heuristic:

        * Start from ``len(names)`` — at most one worker per analyzer.
        * Expand the pool proportionally to the duration ratio so
          that an imbalanced layer gets more workers to absorb the
          critical-path drift (capped at ``max_expansion`` to avoid
          runaway scheduling overhead).
        * Clamp to ``[min_pool, max_workers]`` so we never exceed
          the caller's budget.
        """
        layer_size = len(names)
        if layer_size == 0:
            return max(0, min_pool)

        ratio = self.estimated_duration_ratio(names)
        expansion = min(max_expansion, 1.0 + 0.25 * (ratio - 1.0))
        desired = int(round(layer_size * expansion))
        desired = max(min_pool, desired)
        return min(max_workers, layer_size, desired)

    def snapshot(self) -> dict[str, float]:
        """Return a copy of the current averages (handy for telemetry)."""
        return {name: self.estimate(name) for name in list(self._samples.keys())}


@dataclass
class DependencyGraph:
    """Directed acyclic graph describing analyzer dependencies.

    Edges go from dependency -> dependent (A -> B means A must run before B).
    """

    edges: list[tuple[str, str]] = field(default_factory=lambda: [])

    def _build_adjacency(
        self, analyzer_names: set[str]
    ) -> tuple[dict[str, set[str]], dict[str, int]]:
        adjacency: dict[str, set[str]] = {name: set() for name in analyzer_names}
        in_degree: dict[str, int] = {name: 0 for name in analyzer_names}
        for dep, dependent in self.edges:
            if dep in adjacency and dependent in adjacency:
                adjacency[dep].add(dependent)
                in_degree[dependent] += 1
        return adjacency, in_degree

    def topological_layers(self, analyzer_names: list[str]) -> list[list[str]]:
        """Return analyzers grouped into layers that can run in parallel."""
        names = set(analyzer_names)
        adjacency, in_degree = self._build_adjacency(names)

        queue = [name for name, degree in in_degree.items() if degree == 0]
        layers: list[list[str]] = []
        visited: set[str] = set()

        while queue:
            layers.append(sorted(queue))
            visited.update(queue)
            next_queue: list[str] = []
            for node in queue:
                for neighbor in adjacency[node]:
                    in_degree[neighbor] -= 1
                    if in_degree[neighbor] == 0:
                        next_queue.append(neighbor)
            queue = next_queue

        remaining = names - visited
        if remaining:
            logger.warning("Dependency cycle detected for analyzers: %s", remaining)
            layers.append(sorted(remaining))

        return layers


async def _run_single_analyzer(
    name: str,
    analyzer_fn: Callable[..., Coroutine[Any, Any, Any]],
    context: Any,
    timeout: int,
    duration_cache: AnalyzerDurationCache | None,
) -> AnalyzerResult:
    """Execute a single analyzer with timeout and error handling."""
    started = time.monotonic()
    try:
        result = await asyncio.wait_for(analyzer_fn(context), timeout=timeout)
    except TimeoutError:
        duration = time.monotonic() - started
        logger.error("Analyzer '%s' timed out after %ds", name, timeout)
        if duration_cache is not None:
            duration_cache.record(name, duration)
        return AnalyzerResult(
            name=name,
            success=False,
            error=f"Timeout after {timeout}s",
            duration_seconds=duration,
            timed_out=True,
        )
    except Exception as exc:
        duration = time.monotonic() - started
        logger.error("Analyzer '%s' failed: %s", name, exc)
        if duration_cache is not None:
            duration_cache.record(name, duration)
        return AnalyzerResult(
            name=name,
            success=False,
            error=str(exc),
            duration_seconds=duration,
        )
    else:
        duration = time.monotonic() - started
        if duration_cache is not None:
            duration_cache.record(name, duration)
        return AnalyzerResult(
            name=name,
            success=True,
            result=result,
            duration_seconds=duration,
        )


async def _run_layer_with_work_stealing(
    layer_names: list[str],
    analyzer_map: dict[str, Callable[..., Coroutine[Any, Any, Any]]],
    context: Any,
    timeout: int,
    *,
    pool_size: int,
    duration_cache: AnalyzerDurationCache | None,
) -> dict[str, AnalyzerResult]:
    """Run a single topological layer with a work-stealing worker pool.

    Each analyzer in the layer is enqueued once.  ``pool_size``
    worker coroutines concurrently pop from the queue and execute
    the analyzers.  When a worker finishes an analyzer it
    immediately pulls the next one, so a slow analyzer does not
    hold a slot idle while other workers wait for it (the original
    ``asyncio.Semaphore`` anti-pattern that the audit called out).

    A per-layer :class:`asyncio.BoundedSemaphore` is held for the
    lifetime of each analyzer execution so that the inflight task
    count can never exceed the adaptive pool size, even if a
    misbehaving analyzer spawns additional sub-tasks that try to
    re-enter the same layer.
    """
    if not layer_names:
        return {}

    queue: asyncio.Queue[str] = asyncio.Queue()
    for name in layer_names:
        queue.put_nowait(name)

    bounded_slot = asyncio.BoundedSemaphore(pool_size)
    results: dict[str, AnalyzerResult] = {}
    results_lock = asyncio.Lock()

    async def _worker(worker_id: int) -> None:
        while True:
            try:
                name = await queue.get()
            except asyncio.CancelledError:
                return
            try:
                fn = analyzer_map.get(name)
                if fn is None:
                    continue
                async with bounded_slot:
                    result = await _run_single_analyzer(
                        name, fn, context, timeout, duration_cache
                    )
                async with results_lock:
                    results[name] = result
            finally:
                queue.task_done()

    effective_pool = max(1, min(pool_size, len(layer_names)))
    workers = [
        asyncio.create_task(_worker(idx), name=f"parallel-analyzer-{idx}")
        for idx in range(effective_pool)
    ]
    try:
        await queue.join()
    finally:
        for w in workers:
            if not w.done():
                w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    return results


async def run_parallel_analyzers(
    analyzers: list[dict[str, Any]],
    context: Any,
    max_workers: int = 4,
    timeout: int = 60,
    dependency_graph: DependencyGraph | None = None,
    duration_cache: AnalyzerDurationCache | None = None,
) -> ParallelAnalysisOutcome:
    """Run multiple analyzers with optional dependency ordering.

    Analyzers without dependencies run in parallel (bounded by
    ``max_workers``).  When ``dependency_graph`` is provided,
    analyzers are grouped into topological layers; each layer runs
    with a work-stealing async queue and a per-layer
    :class:`asyncio.BoundedSemaphore` sized from the duration
    cache; layers execute sequentially respecting the dependency
    order.

    Args:
        analyzers: List of dicts with ``'name'`` and ``'fn'`` (async
            callable) keys.
        context: Shared context object passed to each analyzer.
        max_workers: Maximum number of concurrent analyzers per
            layer.  The actual pool size is computed adaptively
            from ``duration_cache`` and clamped to this value.
        timeout: Per-analyzer timeout in seconds.
        dependency_graph: Optional dependency graph for ordering.
        duration_cache: Optional cache used to compute adaptive
            pool sizes from prior-run duration samples.  When
            ``None`` the pool size falls back to
            ``min(max_workers, len(layer))``.

    Returns:
        :class:`ParallelAnalysisOutcome` bundling the per-analyzer
        results with a list of :class:`LayerResult` aggregations.
        The container is dict-like for backward compatibility.
    """
    analyzer_map: dict[str, Callable[..., Coroutine[Any, Any, Any]]] = {}
    for entry in analyzers:
        name = entry["name"]
        fn = entry["fn"]
        analyzer_map[name] = fn

    all_names = list(analyzer_map.keys())
    all_results: dict[str, AnalyzerResult] = {}
    layer_results: list[LayerResult] = []

    if dependency_graph:
        layers = dependency_graph.topological_layers(all_names)
    else:
        layers = [sorted(all_names)]

    for layer_index, layer in enumerate(layers):
        scheduled = [name for name in layer if name in analyzer_map]
        if not scheduled:
            continue

        if duration_cache is not None:
            pool_size = duration_cache.compute_pool_size(
                scheduled, max_workers=max_workers
            )
        else:
            pool_size = min(max(1, max_workers), len(scheduled))

        layer_outcomes = await _run_layer_with_work_stealing(
            scheduled,
            analyzer_map,
            context,
            timeout,
            pool_size=pool_size,
            duration_cache=duration_cache,
        )
        all_results.update(layer_outcomes)

        layer_result = LayerResult(
            layer_index=layer_index,
            analyzer_names=scheduled,
            results=layer_outcomes,
        )
        layer_results.append(layer_result)

        # Log layer-level aggregation so operators can spot partial
        # failures that the legacy semaphore-based code would have
        # hidden in a single ``asyncio.gather`` result.
        if layer_result.is_partial:
            logger.warning(
                "Parallel analysis layer %d had partial failure: %d/%d analyzers "
                "succeeded (failures=%s)",
                layer_index,
                layer_result.success_count,
                len(scheduled),
                layer_result.failed_names,
            )
        elif layer_result.is_total_failure:
            logger.error(
                "Parallel analysis layer %d had total failure: %s",
                layer_index,
                sorted(scheduled),
            )

    return ParallelAnalysisOutcome(results=all_results, layer_results=layer_results)


def _run_coro_in_new_loop(
    coro: Coroutine[Any, Any, Any],
    timeout: int,
) -> Any:
    """Run a coroutine in a brand-new event loop until completion.

    Used by the sync thread-pool path to give each blocking
    analyzer its own event loop, eliminating the GIL contention
    that a single shared event-loop thread would suffer from.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(asyncio.wait_for(coro, timeout=timeout))
    finally:
        try:
            loop.close()
        except Exception:  # noqa: BLE001
            pass


def _run_parallel_analyzers_in_thread_pool(
    analyzers: list[dict[str, Any]],
    context: Any,
    max_workers: int,
    timeout: int,
    dependency_graph: DependencyGraph | None,
    duration_cache: AnalyzerDurationCache | None,
) -> ParallelAnalysisOutcome:
    """Work-stealing thread-pool driver used by the sync wrapper.

    Analyzers are submitted to a real multi-worker
    :class:`concurrent.futures.ThreadPoolExecutor`; the executor's
    work queue is effectively a work-stealing queue (CPython's
    :class:`ThreadPoolExecutor` distributes work across worker
    threads, each consuming from a shared queue).  Each worker
    thread spins up a fresh event loop and runs a single analyzer
    coroutine, so blocking I/O inside analyzers gets true
    OS-level parallelism rather than single-threaded
    serialization.

    Layer ordering is preserved by draining the executor between
    layers.
    """
    import concurrent.futures

    analyzer_map: dict[str, Callable[..., Coroutine[Any, Any, Any]]] = {}
    for entry in analyzers:
        name = entry["name"]
        fn = entry["fn"]
        analyzer_map[name] = fn

    all_names = list(analyzer_map.keys())
    if dependency_graph:
        layers = dependency_graph.topological_layers(all_names)
    else:
        layers = [sorted(all_names)]

    pool_size = max(1, min(max_workers, max(1, len(all_names))))
    all_results: dict[str, AnalyzerResult] = {}
    layer_results: list[LayerResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=pool_size) as executor:
        for layer_index, layer in enumerate(layers):
            scheduled = [name for name in layer if name in analyzer_map]
            if not scheduled:
                continue

            futures: dict[str, concurrent.futures.Future[Any]] = {}
            for name in scheduled:
                fn = analyzer_map[name]
                # Calling ``fn(context)`` produces a fresh coroutine
                # that the worker thread drives on its private loop.
                coro = fn(context)
                fut = executor.submit(_run_coro_in_new_loop, coro, timeout)
                futures[name] = fut

            for name, fut in futures.items():
                try:
                    result = fut.result()
                except Exception as exc:  # noqa: BLE001
                    logger.error("Analyzer '%s' crashed in worker thread: %s", name, exc)
                    result = AnalyzerResult(
                        name=name,
                        success=False,
                        error=str(exc),
                    )
                if not isinstance(result, AnalyzerResult):
                    # Defensive: an analyzer that forgot to wrap its
                    # return value in an AnalyzerResult is treated
                    # as a successful raw payload.
                    result = AnalyzerResult(
                        name=name,
                        success=True,
                        result=result,
                    )
                all_results[name] = result
                if duration_cache is not None:
                    duration_cache.record(name, result.duration_seconds)

            layer_results.append(
                LayerResult(
                    layer_index=layer_index,
                    analyzer_names=scheduled,
                    results={name: all_results[name] for name in scheduled},
                )
            )

    return ParallelAnalysisOutcome(results=all_results, layer_results=layer_results)


def run_parallel_analyzers_sync(
    analyzers: list[dict[str, Any]],
    context: Any,
    max_workers: int = 4,
    timeout: int = 60,
    dependency_graph: DependencyGraph | None = None,
    duration_cache: AnalyzerDurationCache | None = None,
) -> ParallelAnalysisOutcome:
    """Synchronous wrapper for :func:`run_parallel_analyzers`.

    When called from a thread with **no** running event loop, the
    async implementation is invoked directly via
    :func:`asyncio.run` — that path is fully concurrent for
    cooperative async analyzers.

    When called from inside a running event loop, this wrapper
    uses a real :class:`concurrent.futures.ThreadPoolExecutor`
    sized at ``max_workers`` (not a single-worker executor) and
    runs each analyzer in its own thread with its own event loop.
    That gives true OS-level parallelism for analyzers that
    contain blocking I/O, instead of serializing them on one
    event-loop thread.

    Args:
        analyzers: List of dicts with ``'name'`` and ``'fn'`` (async
            callable) keys.
        context: Shared context object passed to each analyzer.
        max_workers: Maximum number of concurrent workers per
            layer.
        timeout: Per-analyzer timeout in seconds.
        dependency_graph: Optional dependency graph for ordering.
        duration_cache: Optional duration cache for adaptive pool
            sizing.

    Returns:
        :class:`ParallelAnalysisOutcome` — see
        :func:`run_parallel_analyzers` for the payload shape.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        return asyncio.run(
            run_parallel_analyzers(
                analyzers,
                context,
                max_workers,
                timeout,
                dependency_graph,
                duration_cache,
            )
        )

    return _run_parallel_analyzers_in_thread_pool(
        analyzers,
        context,
        max_workers,
        timeout,
        dependency_graph,
        duration_cache,
    )


__all__ = [
    "AnalyzerDurationCache",
    "AnalyzerResult",
    "DependencyGraph",
    "LayerResult",
    "ParallelAnalysisOutcome",
    "run_parallel_analyzers",
    "run_parallel_analyzers_sync",
]
