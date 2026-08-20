from enum import StrEnum
from typing import Any


class FindingLifecycleState(StrEnum):
    DETECTED = "detected"
    VALIDATED = "validated"
    EXPLOITABLE = "exploitable"
    REPORTABLE = "reportable"
    FALSE_POSITIVE = "false_positive"


_STICKY_STATES: frozenset[FindingLifecycleState] = frozenset(
    {FindingLifecycleState.REPORTABLE, FindingLifecycleState.FALSE_POSITIVE}
)

_ALLOWED_TRANSITIONS: dict[FindingLifecycleState, set[FindingLifecycleState]] = {
    FindingLifecycleState.DETECTED: {
        FindingLifecycleState.VALIDATED,
        FindingLifecycleState.EXPLOITABLE,
        FindingLifecycleState.FALSE_POSITIVE,
    },
    FindingLifecycleState.VALIDATED: {
        FindingLifecycleState.EXPLOITABLE,
        FindingLifecycleState.REPORTABLE,
        FindingLifecycleState.FALSE_POSITIVE,
    },
    FindingLifecycleState.EXPLOITABLE: {
        FindingLifecycleState.REPORTABLE,
        FindingLifecycleState.FALSE_POSITIVE,
    },
    FindingLifecycleState.REPORTABLE: {FindingLifecycleState.FALSE_POSITIVE},
    FindingLifecycleState.FALSE_POSITIVE: set(),
}


def normalize_lifecycle_state(value: str | None) -> FindingLifecycleState:
    lowered = str(value or "").strip().lower()
    for state in FindingLifecycleState:
        if lowered == state.value:
            return state
    return FindingLifecycleState.DETECTED


def can_transition(current: FindingLifecycleState, target: FindingLifecycleState) -> bool:
    """Return True if a transition from ``current`` to ``target`` is allowed.

    Self-transitions (current == target) are always allowed so callers can
    safely re-apply lifecycle inference without raising.
    """
    if current == target:
        return True
    return target in _ALLOWED_TRANSITIONS.get(current, set())


def transition_state(current: str | None, target: str | None) -> str:
    """Apply a lifecycle transition.

    Illegal transitions keep the existing state instead of raising so a
    single finding cannot take down report generation.
    REPORTABLE and FALSE_POSITIVE are sticky against inferred downgrades.
    """
    destination = normalize_lifecycle_state(target)
    if current is None:
        return destination.value
    source = normalize_lifecycle_state(current)
    if source == destination:
        return source.value
    if source is FindingLifecycleState.FALSE_POSITIVE:
        return source.value
    if (
        source is FindingLifecycleState.REPORTABLE
        and destination is not FindingLifecycleState.FALSE_POSITIVE
    ):
        return source.value
    if not can_transition(source, destination):
        return source.value
    return destination.value


def infer_lifecycle_state(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "")).strip().lower()
    evidence = finding.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}
    validation_state = (
        str(finding.get("validation_state") or evidence.get("validation_state") or "")
        .strip()
        .lower()
    )
    verified = bool(
        finding.get("verified")
        or finding.get("exploit_verified")
        or evidence.get("confirmed")
        or evidence.get("validation_confirmed")
    )
    decision = str(finding.get("decision", "")).strip().upper()
    status = str(finding.get("status", "")).strip().lower()

    if decision in {"FALSE_POSITIVE", "FP", "FALSE-POSITIVE"} or status in {
        "false_positive",
        "fp",
    }:
        return FindingLifecycleState.FALSE_POSITIVE.value
    if decision in {"KEEP"} and severity in {"high", "critical"}:
        return FindingLifecycleState.REPORTABLE.value
    if verified or validation_state in {"active_ready", "confirmed"}:
        return FindingLifecycleState.EXPLOITABLE.value
    if validation_state not in {
        "",
        "passive_only",
        "heuristic_candidate",
        "response_similarity_match",
    }:
        return FindingLifecycleState.VALIDATED.value
    return FindingLifecycleState.DETECTED.value


def apply_lifecycle(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        current = item.get("lifecycle_state")
        source = normalize_lifecycle_state(current) if current is not None else None
        if source in _STICKY_STATES:
            item["lifecycle_state"] = source.value
            normalized.append(item)
            continue
        inferred = infer_lifecycle_state(item)
        item["lifecycle_state"] = transition_state(current, inferred)
        normalized.append(item)
    return normalized
