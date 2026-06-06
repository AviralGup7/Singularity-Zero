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
