"""Workflow expression evaluator for conditional automation tasks.

Mirrors :mod:`src.pipeline.services.pipeline_orchestrator._graph_dsl`
with a finding-scoped variant: instead of evaluating against the
live pipeline context, the expressions here evaluate against a single
:class:`Mapping` finding.  This lets the manual-queue builder attach
a conditional workflow manifest to each finding rather than a flat
list of automation tasks.

Expression grammar
------------------

The DSL is intentionally tiny.  Each expression is a dataclass
implementing :meth:`evaluate`:

* :class:`FieldEquals`         — ``finding[key] == value``
* :class:`FieldMatches`        — ``re.search(pattern, finding[key])``
* :class:`ConfidenceAtLeast`   — ``finding["confidence"] >= threshold``
* :class:`SeverityAtLeast`     — ``finding["severity"] >= threshold``
* :class:`HasSignal`           — ``signal in finding["signals"]``
* :class:`All`                 — logical AND
* :class:`AnyOf`               — logical OR
* :class:`Not`                 — logical NOT

Tasks
-----

:class:`AutomationTask` wraps an existing :class:`TaskDescriptor`
(from :func:`src.analysis.automation.manual_queue.build_automation_tasks`)
with a :class:`WorkflowExpression` guard.  A :class:`Workflow` is a
list of :class:`AutomationTask` objects; :func:`evaluate_workflow`
returns the subset whose guards evaluate to ``True`` for a given
finding.

Example
-------

::

    workflow = Workflow(
        tasks=[
            AutomationTask(
                kind="replay_variant_anonymous",
                title="Replay without auth",
                guard=All((
                    FieldEquals("category", "access_control"),
                    ConfidenceAtLeast(0.85),
                )),
            ),
            AutomationTask(
                kind="run_curl_poc",
                title="Execute stored PoC",
                guard=FieldEquals("category", "idor"),
            ),
        ]
    )
    selected = evaluate_workflow(workflow, finding)
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


class WorkflowExpression(Protocol):
    """Pure predicate evaluated against a single finding dict."""

    def evaluate(self, finding: Mapping[str, Any]) -> bool: ...


@dataclass(frozen=True)
class FieldEquals:
    """True iff ``finding[field] == value`` (case-insensitive string compare)."""

    field: str
    value: str

    def evaluate(self, finding: Mapping[str, Any]) -> bool:
        actual = finding.get(self.field)
        if actual is None:
            return False
        return str(actual).strip().lower() == str(self.value).strip().lower()


@dataclass(frozen=True)
class FieldMatches:
    """True iff ``re.search(pattern, finding[field])`` matches."""

    field: str
    pattern: str

    def evaluate(self, finding: Mapping[str, Any]) -> bool:
        actual = finding.get(self.field)
        if actual is None:
            return False
        try:
            return bool(re.search(self.pattern, str(actual), re.IGNORECASE))
        except re.error:
            return False


@dataclass(frozen=True)
class ConfidenceAtLeast:
    threshold: float

    def evaluate(self, finding: Mapping[str, Any]) -> bool:
        try:
            return float(finding.get("confidence", 0.0)) >= float(self.threshold)
        except (TypeError, ValueError):
            return False


@dataclass(frozen=True)
class SeverityAtLeast:
    threshold: str

    def evaluate(self, finding: Mapping[str, Any]) -> bool:
        actual = str(finding.get("severity", "info")).lower()
        if actual not in SEVERITY_ORDER:
            actual = "info"
        target = str(self.threshold).lower()
        if target not in SEVERITY_ORDER:
            return False
        return SEVERITY_ORDER.index(actual) >= SEVERITY_ORDER.index(target)


@dataclass(frozen=True)
class HasSignal:
    signal: str

    def evaluate(self, finding: Mapping[str, Any]) -> bool:
        signals = finding.get("signals") or []
        if not isinstance(signals, (list, tuple, set, frozenset)):
            return False
        return self.signal in {str(s) for s in signals}


@dataclass(frozen=True)
class All:
    """Logical AND across a tuple of expressions (short-circuits)."""

    expressions: tuple[WorkflowExpression, ...]

    def evaluate(self, finding: Mapping[str, Any]) -> bool:
        return all(e.evaluate(finding) for e in self.expressions)


@dataclass(frozen=True)
class AnyOf:
    """Logical OR across a tuple of expressions (short-circuits)."""

    expressions: tuple[WorkflowExpression, ...]

    def evaluate(self, finding: Mapping[str, Any]) -> bool:
        return any(e.evaluate(finding) for e in self.expressions)


@dataclass(frozen=True)
class Not:
    expression: WorkflowExpression

    def evaluate(self, finding: Mapping[str, Any]) -> bool:
        return not self.expression.evaluate(finding)


@dataclass(frozen=True)
class AutomationTask:
    """A guarded automation task.

    Mirrors the dict shape produced by
    :func:`src.analysis.automation.manual_queue.build_automation_tasks`
    so the manual queue can swap a flat list for an evaluated
    :class:`Workflow` without changing the executor's contract.
    """

    kind: str
    title: str
    guard: WorkflowExpression = field(default_factory=lambda: AlwaysTrue())
    command: str = ""
    url: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_descriptor(self) -> dict[str, Any]:
        descriptor: dict[str, Any] = {
            "kind": self.kind,
            "title": self.title,
        }
        if self.command:
            descriptor["command"] = self.command
        if self.url:
            descriptor["url"] = self.url
        if self.metadata:
            descriptor["metadata"] = dict(self.metadata)
        return descriptor


@dataclass(frozen=True)
class AlwaysTrue:
    """Default guard: a task with no condition is always eligible."""

    def evaluate(self, finding: Mapping[str, Any]) -> bool:  # noqa: ARG002
        return True


@dataclass(frozen=True)
class Workflow:
    """An ordered collection of :class:`AutomationTask` objects.

    A workflow can be reused across many findings: the operator
    authors it once, then :func:`evaluate_workflow` runs it against
    each finding in the manual-queue builder.
    """

    tasks: tuple[AutomationTask, ...] = ()

    def evaluate(self, finding: Mapping[str, Any]) -> tuple[AutomationTask, ...]:
        return tuple(task for task in self.tasks if task.guard.evaluate(finding))


def evaluate_workflow(
    workflow: Workflow, finding: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Return the task descriptors whose guards evaluate to ``True``."""
    selected = workflow.evaluate(finding)
    return [task.to_descriptor() for task in selected]


def default_workflow() -> Workflow:
    """The default workflow that mirrors the existing flat-list behaviour.

    Kept as a function (not a constant) so callers that mutate
    :class:`AutomationTask` instances get fresh objects on every call
    and tests can extend the workflow without polluting the module
    state.
    """
    return Workflow(
        tasks=(
            AutomationTask(
                kind="replay_variant_inherit",
                title="Replay Variant (Inherited Auth)",
                guard=All(
                    (
                        FieldEquals("category", "behavioral_deviation"),
                        SeverityAtLeast("medium"),
                    )
                ),
            ),
            AutomationTask(
                kind="replay_variant_anonymous",
                title="Replay Variant (Anonymous)",
                guard=All(
                    (
                        AnyOf(
                            (
                                FieldEquals("category", "access_control"),
                                FieldEquals("category", "auth_bypass_no_auth"),
                                FieldEquals("category", "auth_bypass_invalid_token"),
                            )
                        ),
                        ConfidenceAtLeast(0.7),
                    )
                ),
            ),
            AutomationTask(
                kind="run_curl_poc",
                title="Run curl PoC",
                guard=ConfidenceAtLeast(0.6),
            ),
            AutomationTask(
                kind="run_python_poc",
                title="Run Python PoC",
                guard=ConfidenceAtLeast(0.6),
            ),
            AutomationTask(
                kind="collect_api_baseline",
                title="Collect API baseline and compare statuses",
                guard=FieldEquals("category", "api"),
            ),
        )
    )


def apply_workflow_to_findings(
    findings: Iterable[Mapping[str, Any]],
    *,
    workflow: Workflow | None = None,
) -> list[dict[str, Any]]:
    """Project a sequence of findings into selected automation tasks.

    Each output entry is a dict shaped like the queue's existing
    ``automation_tasks`` field so :class:`AutomationTaskExecutor` can
    consume the result without modification.
    """
    wf = workflow if workflow is not None else default_workflow()
    out: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        out.extend(evaluate_workflow(wf, finding))
    return out


def from_dict(expression: Mapping[str, Any]) -> WorkflowExpression:
    """Materialise a :class:`WorkflowExpression` from a dict descriptor.

    Supports the following ``op`` values: ``eq``, ``matches``, ``confidence_at_least``,
    ``severity_at_least``, ``has_signal``, ``all``, ``any``, ``not``, ``always``.

    The companion :func:`workflow_to_dict` is a JSON-safe round-trip
    helper so operators can persist workflows in TOML/YAML.
    """
    op = str(expression.get("op", "always")).lower()
    if op == "eq":
        return FieldEquals(field=str(expression["field"]), value=str(expression["value"]))
    if op == "matches":
        return FieldMatches(field=str(expression["field"]), pattern=str(expression["pattern"]))
    if op == "confidence_at_least":
        return ConfidenceAtLeast(threshold=float(expression["threshold"]))
    if op == "severity_at_least":
        return SeverityAtLeast(threshold=str(expression["threshold"]))
    if op == "has_signal":
        return HasSignal(signal=str(expression["signal"]))
    if op == "all":
        return All(expressions=tuple(from_dict(e) for e in expression.get("expressions", [])))
    if op == "any":
        return AnyOf(expressions=tuple(from_dict(e) for e in expression.get("expressions", [])))
    if op == "not":
        return Not(expression=from_dict(expression["expression"]))
    if op == "always":
        return AlwaysTrue()
    raise ValueError(f"unknown workflow expression op: {op!r}")


def expression_to_dict(expr: WorkflowExpression) -> dict[str, Any]:
    if isinstance(expr, FieldEquals):
        return {"op": "eq", "field": expr.field, "value": expr.value}
    if isinstance(expr, FieldMatches):
        return {"op": "matches", "field": expr.field, "pattern": expr.pattern}
    if isinstance(expr, ConfidenceAtLeast):
        return {"op": "confidence_at_least", "threshold": expr.threshold}
    if isinstance(expr, SeverityAtLeast):
        return {"op": "severity_at_least", "threshold": expr.threshold}
    if isinstance(expr, HasSignal):
        return {"op": "has_signal", "signal": expr.signal}
    if isinstance(expr, All):
        return {"op": "all", "expressions": [expression_to_dict(e) for e in expr.expressions]}
    if isinstance(expr, AnyOf):
        return {"op": "any", "expressions": [expression_to_dict(e) for e in expr.expressions]}
    if isinstance(expr, Not):
        return {"op": "not", "expression": expression_to_dict(expr.expression)}
    if isinstance(expr, AlwaysTrue):
        return {"op": "always"}
    raise TypeError(f"unsupported expression type: {type(expr).__name__}")


__all__ = [
    "All",
    "AlwaysTrue",
    "AnyOf",
    "AutomationTask",
    "ConfidenceAtLeast",
    "FieldEquals",
    "FieldMatches",
    "HasSignal",
    "Not",
    "SEVERITY_ORDER",
    "SeverityAtLeast",
    "Workflow",
    "WorkflowExpression",
    "apply_workflow_to_findings",
    "default_workflow",
    "evaluate_workflow",
    "expression_to_dict",
    "from_dict",
]
