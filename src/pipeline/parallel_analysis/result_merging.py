"""Result types and duration cache for parallel analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
    """Aggregated outcome of a single topological layer."""

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
        return bool(self.results) and self.success_count == 0

    @property
    def is_partial(self) -> bool:
        return 0 < self.success_count < len(self.results)

    @property
    def is_full_success(self) -> bool:
        return bool(self.results) and self.failure_count == 0

    @property
    def fatal_failures(self) -> list[str]:
        return [r.name for r in self.results.values() if r.timed_out]

    @property
    def failed_names(self) -> list[str]:
        return [r.name for r in self.results.values() if not r.success]

    def successful_results(self) -> dict[str, Any]:
        return {
            name: r.result
            for name, r in self.results.items()
            if r.success
        }


@dataclass
class ParallelAnalysisOutcome:
    """Container bundling the per-analyzer map with per-layer metadata."""

    results: dict[str, AnalyzerResult] = field(default_factory=dict)
    layer_results: list[LayerResult] = field(default_factory=list)

    def __getitem__(self, name: str) -> AnalyzerResult:
        return self.results[name]

    def __iter__(self) -> Any:
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)

    def __contains__(self, name: object) -> bool:
        return name in self.results

    def items(self) -> Any:
        return self.results.items()

    def keys(self) -> Any:
        return self.results.keys()

    def values(self) -> Any:
        return self.results.values()

    def get(self, name: str, default: AnalyzerResult | None = None) -> AnalyzerResult | None:
        return self.results.get(name, default)

    @property
    def has_partial_failure(self) -> bool:
        return any(layer.is_partial for layer in self.layer_results)

    @property
    def has_total_failure(self) -> bool:
        return any(layer.is_total_failure for layer in self.layer_results)

    @property
    def all_timed_out(self) -> list[str]:
        return [name for layer in self.layer_results for name in layer.fatal_failures]


class AnalyzerDurationCache:
    """In-memory cache of recent analyzer durations."""

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
        if duration < 0:
            return
        samples = self._samples.setdefault(name, [])
        samples.append(float(duration))
        if len(samples) > self._max_entries:
            del samples[0 : len(samples) - self._max_entries]

    def estimate(self, name: str) -> float:
        samples = self._samples.get(name)
        if not samples:
            return self._default_duration
        return sum(samples) / len(samples)

    def estimated_duration_ratio(self, names: list[str]) -> float:
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
        layer_size = len(names)
        if layer_size == 0:
            return max(0, min_pool)

        ratio = self.estimated_duration_ratio(names)
        expansion = min(max_expansion, 1.0 + 0.25 * (ratio - 1.0))
        desired = int(round(layer_size * expansion))
        desired = max(min_pool, desired)
        return min(max_workers, layer_size, desired)

    def snapshot(self) -> dict[str, float]:
        return {name: self.estimate(name) for name in list(self._samples.keys())}

    def save(self, cache: Any, namespace: str = "analysis:duration_histogram") -> None:
        try:
            snapshot = self.snapshot()
            cache.set(f"{namespace}:{id(self)}", snapshot, ttl=86400 * 30)
        except Exception as exc:
            logger.warning("Operation failed in result_merging.py: %s", exc, exc_info=True)  # noqa: BLE001

    @classmethod
    def load(cls, cache: Any, namespace: str = "analysis:duration_histogram", key_id: int | None = None) -> AnalyzerDurationCache:
        inst = cls()
        if key_id is not None:
            try:
                snapshot = cache.get(f"{namespace}:{key_id}")
                if isinstance(snapshot, dict):
                    for name, dur in snapshot.items():
                        inst.record(name, dur)
            except Exception as exc:
                logger.warning("Operation failed in result_merging.py: %s", exc, exc_info=True)  # noqa: BLE001
        return inst


@dataclass
class DependencyGraph:
    """Directed acyclic graph describing analyzer dependencies."""

    edges: list[tuple[str, str]] = field(default_factory=lambda: [])

    def _build_adjacency(
        self, analyzer_names: list[str]
    ) -> tuple[dict[str, set[str]], dict[str, int]]:
        adjacency: dict[str, set[str]] = {name: set() for name in analyzer_names}
        in_degree: dict[str, int] = {name: 0 for name in analyzer_names}
        for dep, dependent in self.edges:
            if dep in adjacency and dependent in adjacency:
                adjacency[dep].add(dependent)
                in_degree[dependent] += 1
        return adjacency, in_degree

    def topological_layers(self, analyzer_names: list[str]) -> list[list[str]]:
        from src.core.logging.trace_logging import get_pipeline_logger

        logger = get_pipeline_logger(__name__)
        names_set: set[str] = set(analyzer_names)
        names: list[str] = list(names_set)
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

        remaining = names_set - visited
        if remaining:
            logger.warning("Dependency cycle detected for analyzers: %s", remaining)
            layers.append(sorted(remaining))

        return layers
