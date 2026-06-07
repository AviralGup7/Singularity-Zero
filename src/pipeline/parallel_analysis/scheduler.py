"""Scheduler: sync wrapper and thread-pool driver for parallel analyzers."""

from __future__ import annotations

import asyncio
import concurrent.futures
import threading
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


_WORKER_LOOP_LOCAL: threading.local = threading.local()


def _get_worker_event_loop() -> asyncio.AbstractEventLoop:
    """Return a persistent event loop for the current worker thread."""
    loop = getattr(_WORKER_LOOP_LOCAL, "loop", None)
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        _WORKER_LOOP_LOCAL.loop = loop
    return loop


def _run_coro_in_new_loop(
    coro: Coroutine[Any, Any, Any],
    timeout: int,
) -> Any:
    loop = _get_worker_event_loop()
    try:
        return loop.run_until_complete(asyncio.wait_for(coro, timeout=timeout))
    except Exception:
        return None


def _run_parallel_analyzers_in_thread_pool(
    analyzers: list[dict[str, Any]],
    context: Any,
    max_workers: int,
    timeout: int,
    dependency_graph: Any,
    duration_cache: AnalyzerDurationCache | None,
) -> ParallelAnalysisOutcome:
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
                coro = fn(context)
                fut = executor.submit(_run_coro_in_new_loop, coro, timeout)
                futures[name] = fut

            for name, fut in futures.items():
                try:
                    result = fut.result()
                except Exception as exc:
                    logger.error("Analyzer '%s' crashed in worker thread: %s", name, exc)
                    result = AnalyzerResult(
                        name=name,
                        success=False,
                        error=str(exc),
                    )
                if not isinstance(result, AnalyzerResult):
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
    dependency_graph: Any = None,
    duration_cache: AnalyzerDurationCache | None = None,
) -> ParallelAnalysisOutcome:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        from src.pipeline.parallel_analysis.executor import run_parallel_analyzers

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
