from enum import StrEnum
from typing import Any


class FindingLifecycleState(StrEnum):
    DETECTED = "detected"
    VALIDATED = "validated"
    EXPLOITABLE = "exploitable"
    REPORTABLE = "reportable"


_ALLOWED_TRANSITIONS: dict[FindingLifecycleState, set[FindingLifecycleState]] = {
    FindingLifecycleState.DETECTED: {
        FindingLifecycleState.DETECTED,
        FindingLifecycleState.VALIDATED,
        FindingLifecycleState.EXPLOITABLE,
        FindingLifecycleState.REPORTABLE,
    },
    FindingLifecycleState.VALIDATED: {
        FindingLifecycleState.VALIDATED,
        FindingLifecycleState.EXPLOITABLE,
        FindingLifecycleState.REPORTABLE,
    },
    FindingLifecycleState.EXPLOITABLE: {
        FindingLifecycleState.EXPLOITABLE,
        FindingLifecycleState.REPORTABLE,
    },
    FindingLifecycleState.REPORTABLE: {
        FindingLifecycleState.REPORTABLE,
    },
}


def normalize_lifecycle_state(value: str | None) -> FindingLifecycleState:
    lowered = str(value or "").strip().lower()
    for state in FindingLifecycleState:
        if lowered == state.value:
            return state
    return FindingLifecycleState.DETECTED


def can_transition(current: FindingLifecycleState, target: FindingLifecycleState) -> bool:
    return target in _ALLOWED_TRANSITIONS[current]


def transition_state(current: str | None, target: str | None) -> str:
    source = normalize_lifecycle_state(current)
    destination = normalize_lifecycle_state(target)
    if can_transition(source, destination):
        return destination.value
    return source.value


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

    if decision in {"KEEP"} and severity in {"high", "critical"}:
        return FindingLifecycleState.REPORTABLE.value
    if verified or validation_state in {"response_similarity_match", "active_ready", "confirmed"}:
        return FindingLifecycleState.EXPLOITABLE.value
    if validation_state not in {"", "passive_only", "heuristic_candidate"}:
        return FindingLifecycleState.VALIDATED.value
    return FindingLifecycleState.DETECTED.value


def apply_lifecycle(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        inferred = infer_lifecycle_state(item)
        item["lifecycle_state"] = transition_state(item.get("lifecycle_state"), inferred)
        normalized.append(item)
    return normalized
