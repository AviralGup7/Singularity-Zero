"""Async executor for parallel analyzers."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.parallel_analysis.result_merging import (
    AnalyzerDurationCache,
    AnalyzerResult,
    LayerResult,
    ParallelAnalysisOutcome,
)

logger = get_pipeline_logger(__name__)

# Streaming context protocol:
#   context.iter_live_hosts()   -> AsyncIterator[str]
#   context.iter_urls()         -> AsyncIterator[str]
#   context.iter_subdomains()   -> AsyncIterator[str]
# Analyzers should prefer streaming over copying full sets.


async def _run_single_analyzer(
    name: str,
    analyzer_fn: Callable[..., Coroutine[Any, Any, Any]],
    context: Any,
    timeout: int,
    duration_cache: AnalyzerDurationCache | None,
) -> AnalyzerResult:
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
    if not layer_names:
        return {}

    _BOUNDED_QUEUE_MAX = 512
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=_BOUNDED_QUEUE_MAX)
    for name in layer_names:
        try:
            queue.put_nowait(name)
        except asyncio.QueueFull:
            await queue.put(name)

    bounded_slot = asyncio.BoundedSemaphore(pool_size)
    results: dict[str, AnalyzerResult] = {}
    results_lock = asyncio.Lock()
    # Bug #11: Track how many workers are running in bypass mode (slot
    # acquisition timed out) so we can warn if the safety valve is being
    # triggered excessively, which indicates a real resource risk.
    _bypass_count = 0
    _BYPASS_WARN_THRESHOLD = max(2, pool_size // 2)

    async def _worker(worker_id: int) -> None:
        nonlocal _bypass_count
        while True:
            try:
                name = await queue.get()
            except asyncio.CancelledError:
                return
            acquired = False
            bypassed = False
            try:
                fn = analyzer_map.get(name)
                if fn is None:
                    continue
                # Use a timeout on slot acquisition to prevent self-deadlock.
                # If an analyzer itself creates nested parallel work that
                # requests the same bounded subsystem, all slots could be
                # held by parent-layer workers, causing permanent deadlock.
                # The timeout lets us fall through with a warning rather
                # than hang forever.
                try:
                    await asyncio.wait_for(bounded_slot.acquire(), timeout=30.0)
                    acquired = True
                except TimeoutError:
                    bypassed = True
                    _bypass_count += 1
                    if _bypass_count >= _BYPASS_WARN_THRESHOLD:
                        logger.warning(
                            "Parallel analyzer '%s' slot bypass active (%d "
                            "workers bypassing limits). This indicates "
                            "possible self-deadlock or pool exhaustion.",
                            name,
                            _bypass_count,
                        )
                result = await _run_single_analyzer(name, fn, context, timeout, duration_cache)
                async with results_lock:
                    results[name] = result
            finally:
                if acquired:
                    bounded_slot.release()
                if bypassed:
                    _bypass_count = max(0, _bypass_count - 1)
                queue.task_done()

    effective_pool = max(1, min(pool_size, len(layer_names)))
    workers: list[asyncio.Task[None]] = []
    # Bug #7: Track how many governor slots were acquired so we always
    # release exactly the right number, even if create_task() fails.
    governor_acquired = 0
    try:
        from src.core.concurrency_governor import get_governor

        governor = get_governor()
        governor_available = True
    except ImportError:
        governor = None  # type: ignore[assignment]
        governor_available = False

    for idx in range(effective_pool):
        # Global governor check: each worker counts toward system-wide
        # concurrency.  If the system is overloaded, reduce the worker
        # count rather than adding more pressure.
        if governor_available and governor is not None:
            if not governor.allow("parallel_analyzers"):
                logger.warning(
                    "Parallel analyzer: global governor limit reached, "
                    "reducing workers from %d to %d",
                    effective_pool,
                    len(workers),
                )
                break
            governor_acquired += 1
        try:
            workers.append(asyncio.create_task(_worker(idx), name=f"parallel-analyzer-{idx}"))
        except Exception:
            # Bug #7: If create_task fails, immediately release the
            # governor slot we just acquired to prevent accounting drift.
            if governor_available and governor is not None:
                governor.release("parallel_analyzers")
                governor_acquired -= 1
            raise
    try:
        await queue.join()
    finally:
        for w in workers:
            if not w.done():
                w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        # Release governor slots for all workers that were created.
        if governor_available and governor is not None:
            for _ in range(governor_acquired):
                governor.release("parallel_analyzers")

    return results


async def run_parallel_analyzers(
    analyzers: list[dict[str, Any]],
    context: Any,
    max_workers: int = 4,
    timeout: int = 60,
    dependency_graph: Any = None,
    duration_cache: AnalyzerDurationCache | None = None,
) -> ParallelAnalysisOutcome:
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
            pool_size = duration_cache.compute_pool_size(scheduled, max_workers=max_workers)
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

    outcome = ParallelAnalysisOutcome(results=all_results, layer_results=layer_results)
    if duration_cache is not None and outcome.results:
        try:
            from src.pipeline.unified_cache import _unified_cache

            uc = _unified_cache
            duration_cache.save(uc)
        except Exception as exc:
            logger.warning("Operation failed in executor.py: %s", exc, exc_info=True)  # noqa: BLE001
    return outcome
