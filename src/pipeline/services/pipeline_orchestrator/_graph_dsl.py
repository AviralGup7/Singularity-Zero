"""Declarative graph DSL for the Neural-Mesh pipeline orchestrator.

Replaces the previous hand-maintained ``STAGE_DEPS`` + ``PARALLEL_STAGE_GROUPS``
duality with a single source of truth: a collection of :class:`StageNode`
objects whose ``needs`` (dependencies) and ``when`` (conditional gating)
expressions fully describe the executable graph.

The DSL is intentionally Python-native (no YAML, no OmegaConf dependency) so
nodes are type-checkable, IDE-discoverable, and easy to compose.  The
runtime cost is zero: nodes are dataclasses and conditions are pure
predicates evaluated by :mod:`actor_scheduler`.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


class StageStatusValue:
    """Local re-export to avoid a hard import on ``core.models``."""

    COMPLETED = "COMPLETED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    RUNNING = "RUNNING"
    PENDING = "PENDING"


class Condition(Protocol):
    """A pure predicate evaluated against the live pipeline context.

    Implementations MUST be pure functions of ``(ctx, state)`` so the
    scheduler can re-evaluate them on every dispatch tick without
    observable side effects.
    """

    def is_satisfied(self, ctx: Any, state: Mapping[str, Any]) -> bool: ...


@dataclass(frozen=True)
class AlwaysTrue:
    """The unconditional default — stage runs as soon as ``needs`` are met."""

    def is_satisfied(self, ctx: Any, state: Mapping[str, Any]) -> bool:  # noqa: ARG002
        return True


@dataclass(frozen=True)
class OutputNonEmpty:
    """True iff the upstream stage completed AND produced a non-empty output.

    ``field`` is the attribute name on ``ctx.result`` to inspect (e.g.
    ``"urls"``, ``"live_hosts"``, ``"subdomains"``).  When ``field`` is
    empty, only the completion check is performed.
    """

    stage: str
    field: str = ""

    def is_satisfied(self, ctx: Any, state: Mapping[str, Any]) -> bool:  # noqa: ARG002
        result = _result_of(ctx)
        status = result.stage_status.get(self.stage)
        if status not in (StageStatusValue.COMPLETED, StageStatusValue.DEGRADED):
            return False
        if not self.field:
            return True
        value = getattr(result, self.field, None)
        if value is None:
            return False
        if isinstance(value, (list, tuple, set, frozenset, dict, str)):
            return len(value) > 0
        return bool(value)


@dataclass(frozen=True)
class StageCompleted:
    """True iff the named stage reached a terminal non-failure status."""

    stage: str

    def is_satisfied(self, ctx: Any, state: Mapping[str, Any]) -> bool:  # noqa: ARG002
        result = _result_of(ctx)
        status = result.stage_status.get(self.stage)
        return status in (
            StageStatusValue.COMPLETED,
            StageStatusValue.DEGRADED,
            StageStatusValue.SKIPPED,
        )


@dataclass(frozen=True)
class StageSucceeded:
    """True iff the named stage completed successfully (no degraded/empty)."""

    stage: str

    def is_satisfied(self, ctx: Any, state: Mapping[str, Any]) -> bool:  # noqa: ARG002
        result = _result_of(ctx)
        return bool(result.stage_status.get(self.stage) == StageStatusValue.COMPLETED)


@dataclass(frozen=True)
class NotFailed:
    """True iff the named stage is not in the FAILED state."""

    stage: str

    def is_satisfied(self, ctx: Any, state: Mapping[str, Any]) -> bool:  # noqa: ARG002
        result = _result_of(ctx)
        return bool(result.stage_status.get(self.stage) != StageStatusValue.FAILED)


@dataclass(frozen=True)
class FlagSet:
    """True iff ``state[flag]`` is truthy.

    Used to gate stages on runtime capabilities (e.g. ``nuclei_available``)
    or operator toggles (``--dry-run``, scope-injection switches).
    """

    flag: str

    def is_satisfied(self, ctx: Any, state: Mapping[str, Any]) -> bool:
        return bool(state.get(self.flag))


@dataclass(frozen=True)
class All:
    """Logical AND across a tuple of conditions (short-circuits)."""

    conditions: tuple[Condition, ...]

    def is_satisfied(self, ctx: Any, state: Mapping[str, Any]) -> bool:
        return all(c.is_satisfied(ctx, state) for c in self.conditions)


@dataclass(frozen=True)
class AnyOf:
    """Logical OR across a tuple of conditions (short-circuits)."""

    conditions: tuple[Condition, ...]

    def is_satisfied(self, ctx: Any, state: Mapping[str, Any]) -> bool:
        return any(c.is_satisfied(ctx, state) for c in self.conditions)


@dataclass(frozen=True)
class Not:
    """Logical negation of a wrapped condition."""

    condition: Condition

    def is_satisfied(self, ctx: Any, state: Mapping[str, Any]) -> bool:
        return not self.condition.is_satisfied(ctx, state)


@dataclass(frozen=True)
class StageNode:
    """Declarative description of a single pipeline stage.

    Attributes
    ----------
    name:
        Stable identifier — must be unique within a graph and is the key
        used in ``stage_status``, ``module_metrics``, and checkpoint
        records.
    needs:
        Tuple of stage names whose completion is a hard prerequisite.
        Order is irrelevant; the scheduler resolves readiness from the
        ``needs`` set.
    when:
        Conditional gate; default is :class:`AlwaysTrue`.  When the
        predicate returns ``False`` the node is *deferred* (not failed)
        and re-evaluated on subsequent dispatch ticks.  A node that
        remains unsatisfiable at pipeline end is recorded as
        ``SKIPPED`` with ``reason="condition_never_satisfied"``.
    weight:
        Priority band.  Higher values are dispatched first when
        multiple nodes become ready simultaneously.  Defaults to 1;
        suggested convention is ``timeout_seconds // 60`` so the
        longest expected stage on the critical path gets first
        access to the worker pool.  ``reporting`` and
        ``active_scan`` should be raised explicitly.
    timeout:
        Optional per-stage timeout override (seconds).  ``None`` means
        "use the orchestrator's resolver".
    critical:
        When ``True``, a fatal failure of this node aborts the run.
        Mirrors the hard-coded ``{"subdomains", "live_hosts", "urls"}``
        set used by the legacy tier runner.
    """

    name: str
    needs: tuple[str, ...] = ()
    when: Condition = field(default_factory=AlwaysTrue)
    weight: int = 1
    timeout: int | None = None
    critical: bool = False


@dataclass(frozen=True)
class Graph:
    """A validated collection of :class:`StageNode` objects.

    The graph is immutable: adding/removing nodes produces a new
    ``Graph``.  Validation runs in ``__post_init__`` and rejects:

    * Unknown dependencies (typo in ``needs``)
    * Duplicate stage names
    * Cycles (detected by Kahn's algorithm)
    * Self-loops
    """

    nodes: tuple[StageNode, ...] = field(default_factory=tuple)
    edges: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        names = [n.name for n in self.nodes]
        if len(set(names)) != len(names):
            dupes = sorted({n for n in names if names.count(n) > 1})
            raise ValueError(f"Duplicate stage names in graph: {dupes}")

        name_set = set(names)
        for n in self.nodes:
            if n.name in n.needs:
                raise ValueError(f"Stage '{n.name}' has a self-dependency in needs")
            for dep in n.needs:
                if dep not in name_set:
                    raise ValueError(f"Stage '{n.name}' depends on unknown stage '{dep}'")

        in_degree: dict[str, int] = {n: 0 for n in name_set}
        adjacency: dict[str, list[str]] = {n: [] for n in name_set}
        for src, dst in self.edges:
            if src not in name_set or dst not in name_set:
                raise ValueError(f"Edge ({src!r} -> {dst!r}) references an unknown stage")
            adjacency[src].append(dst)
            in_degree[dst] += 1

        for node in self.nodes:
            for dep in node.needs:
                if dep == node.name:
                    continue
                if dep not in in_degree:
                    continue
                if node.name not in adjacency[dep]:
                    in_degree[node.name] = in_degree.get(node.name, 0) + 1
                    adjacency[dep].append(node.name)

        queue: deque[str] = deque(n for n, d in in_degree.items() if d == 0)
        visited = 0
        while queue:
            current = queue.popleft()
            visited += 1
            for child in adjacency.get(current, []):
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)
        if visited != len(name_set):
            raise ValueError(
                f"Circular dependency detected in graph: "
                f"visited {visited} of {len(name_set)} stages"
            )

    def get(self, name: str) -> StageNode | None:
        for n in self.nodes:
            if n.name == name:
                return n
        return None

    def require(self, name: str) -> StageNode:
        node = self.get(name)
        if node is None:
            raise KeyError(f"Stage '{name}' is not declared in the graph")
        return node

    def names(self) -> tuple[str, ...]:
        return tuple(n.name for n in self.nodes)

    def downstream_of(self, stage: str) -> tuple[StageNode, ...]:
        """Return the set of nodes that list ``stage`` in their ``needs``."""
        return tuple(n for n in self.nodes if stage in n.needs)

    def topological_sort(self) -> tuple[str, ...]:
        """Return node names in topological order using Kahn's algorithm."""
        name_set = {n.name for n in self.nodes}
        in_degree: dict[str, int] = {n.name: 0 for n in self.nodes}
        adjacency: dict[str, list[str]] = {n.name: [] for n in self.nodes}
        for n in self.nodes:
            for dep in n.needs:
                if dep not in name_set or dep == n.name:
                    continue
                adjacency[dep].append(n.name)
                in_degree[n.name] += 1
        queue: deque[str] = deque(n for n, d in in_degree.items() if d == 0)
        order: list[str] = []
        while queue:
            current = queue.popleft()
            order.append(current)
            for child in adjacency.get(current, []):
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)
        return tuple(order)


def _result_of(ctx: Any) -> Any:
    """Return ``ctx.result`` if present, else ``ctx`` itself.

    The orchestrator hands the scheduler a :class:`PipelineContext`
    whose ``result`` attribute carries the mutable stage outputs.
    Tests sometimes pass a bare ``StageResult``; both are accepted.
    """
    return getattr(ctx, "result", ctx)
