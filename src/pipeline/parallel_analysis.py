"""Parallel analysis orchestrator for running independent analyzers concurrently.

Provides dependency-graph-aware parallel execution of analysis stages using
asyncio.gather(), with per-analyzer error isolation and timeout support.
"""

import asyncio
import time
from collections.abc import Callable, Coroutine
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
) -> AnalyzerResult:
    """Execute a single analyzer with timeout and error handling."""
    started = time.monotonic()
    try:
        result = await asyncio.wait_for(analyzer_fn(context), timeout=timeout)
        duration = time.monotonic() - started
        return AnalyzerResult(
            name=name,
            success=True,
            result=result,
            duration_seconds=duration,
        )
    except TimeoutError:
        duration = time.monotonic() - started
        logger.error("Analyzer '%s' timed out after %ds", name, timeout)
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
        return AnalyzerResult(
            name=name,
            success=False,
            error=str(exc),
            duration_seconds=duration,
        )


def run_parallel_analyzers_sync(
    analyzers: list[dict[str, Any]],
    context: Any,
    max_workers: int = 4,
    timeout: int = 60,
    dependency_graph: DependencyGraph | None = None,
) -> dict[str, AnalyzerResult]:
    """Synchronous wrapper for run_parallel_analyzers.

    Args:
        analyzers: List of dicts with 'name' and 'fn' (async callable) keys.
        context: Shared context object passed to each analyzer.
        max_workers: Maximum number of concurrent analyzers per layer.
        timeout: Per-analyzer timeout in seconds.
        dependency_graph: Optional dependency graph for ordering.

    Returns:
        Dict mapping analyzer name to AnalyzerResult.
    """
    return asyncio.run(
        run_parallel_analyzers(analyzers, context, max_workers, timeout, dependency_graph)
    )


async def run_parallel_analyzers(
    analyzers: list[dict[str, Any]],
    context: Any,
    max_workers: int = 4,
    timeout: int = 60,
    dependency_graph: DependencyGraph | None = None,
) -> dict[str, AnalyzerResult]:
    """Run multiple analyzers with optional dependency ordering.

    Analyzers without dependencies run in parallel (bounded by max_workers).
    When a dependency_graph is provided, analyzers are grouped into
    topological layers; each layer runs in parallel, and layers execute
    sequentially respecting the dependency order.

    Args:
        analyzers: List of dicts with 'name' and 'fn' (async callable) keys.
        context: Shared context object passed to each analyzer.
        max_workers: Maximum number of concurrent analyzers per layer.
        timeout: Per-analyzer timeout in seconds.
        dependency_graph: Optional dependency graph for ordering.

    Returns:
        Dict mapping analyzer name to AnalyzerResult.
    """
    analyzer_map: dict[str, Callable[..., Coroutine[Any, Any, Any]]] = {}
    for entry in analyzers:
        name = entry["name"]
        fn = entry["fn"]
        analyzer_map[name] = fn

    all_names = list(analyzer_map.keys())
    results: dict[str, AnalyzerResult] = {}

    if dependency_graph:
        layers = dependency_graph.topological_layers(all_names)
    else:
        layers = [sorted(all_names)]

    semaphore = asyncio.Semaphore(max_workers)

    async def _bounded_run(
        name: str,
        fn: Callable[..., Coroutine[Any, Any, Any]],
    ) -> AnalyzerResult:
        async with semaphore:
            return await _run_single_analyzer(name, fn, context, timeout)

    for layer in layers:
        tasks = [_bounded_run(name, analyzer_map[name]) for name in layer if name in analyzer_map]
        layer_results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in layer_results:
            if isinstance(res, Exception):
                logger.error("Unexpected error in analyzer layer: %s", res)
                continue
            if isinstance(res, AnalyzerResult):
                results[res.name] = res

    return results


__all__ = [
    "AnalyzerResult",
    "DependencyGraph",
    "run_parallel_analyzers",
    "run_parallel_analyzers_sync",
]
