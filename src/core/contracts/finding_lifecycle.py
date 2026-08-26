from enum import StrEnum
from typing import Any


class FindingLifecycleState(StrEnum):
    """Canonical finding lifecycle.

    Surface machine (F-007): CANDIDATE → REPORTABLE | FALSE_POSITIVE.
    VALIDATED and EXPLOITABLE are refinements of CANDIDATE (still not
    reportable). DETECTED is a legacy alias of CANDIDATE.
    REPORTABLE and FALSE_POSITIVE are sticky.
    """

    CANDIDATE = "candidate"
    DETECTED = "detected"
    VALIDATED = "validated"
    EXPLOITABLE = "exploitable"
    REPORTABLE = "reportable"
    FALSE_POSITIVE = "false_positive"


_CANDIDATE_CLASS: frozenset[FindingLifecycleState] = frozenset(
    {
        FindingLifecycleState.CANDIDATE,
        FindingLifecycleState.DETECTED,
        FindingLifecycleState.VALIDATED,
        FindingLifecycleState.EXPLOITABLE,
    }
)

_STICKY_STATES: frozenset[FindingLifecycleState] = frozenset(
    {FindingLifecycleState.REPORTABLE, FindingLifecycleState.FALSE_POSITIVE}
)


class FindingTicketStatus(StrEnum):
    """Dashboard ticket axis — independent of F-007 surface lifecycle."""

    OPEN = "open"
    CLOSED = "closed"


_TICKET_ONLY: frozenset[str] = frozenset({"open", "closed", "accepted"})

_ALIASES: dict[str, FindingLifecycleState] = {
    "candidate": FindingLifecycleState.CANDIDATE,
    "detected": FindingLifecycleState.CANDIDATE,
    "heuristic_candidate": FindingLifecycleState.CANDIDATE,
    "new": FindingLifecycleState.CANDIDATE,
    "validated": FindingLifecycleState.VALIDATED,
    "exploitable": FindingLifecycleState.EXPLOITABLE,
    "reportable": FindingLifecycleState.REPORTABLE,
    "false_positive": FindingLifecycleState.FALSE_POSITIVE,
    "false-positive": FindingLifecycleState.FALSE_POSITIVE,
    "fp": FindingLifecycleState.FALSE_POSITIVE,
}

_ALLOWED_TRANSITIONS: dict[FindingLifecycleState, set[FindingLifecycleState]] = {
    FindingLifecycleState.CANDIDATE: {
        FindingLifecycleState.VALIDATED,
        FindingLifecycleState.EXPLOITABLE,
        FindingLifecycleState.REPORTABLE,
        FindingLifecycleState.FALSE_POSITIVE,
    },
    FindingLifecycleState.DETECTED: {
        FindingLifecycleState.VALIDATED,
        FindingLifecycleState.EXPLOITABLE,
        FindingLifecycleState.REPORTABLE,
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


def normalize_ticket_status(value: str | None) -> FindingTicketStatus:
    lowered = str(value or "").strip().lower()
    if lowered in {"closed", "accepted", "resolved", "done"}:
        return FindingTicketStatus.CLOSED
    return FindingTicketStatus.OPEN


def normalize_lifecycle_state(value: str | None) -> FindingLifecycleState:
    lowered = str(value or "").strip().lower()
    if lowered in _TICKET_ONLY:
        # Ticket axis, not lifecycle. Missing lifecycle → CANDIDATE.
        return FindingLifecycleState.CANDIDATE
    aliased = _ALIASES.get(lowered)
    if aliased is not None:
        return aliased
    for state in FindingLifecycleState:
        if lowered == state.value:
            return state
    return FindingLifecycleState.CANDIDATE


def surface_lifecycle_state(value: str | FindingLifecycleState | None) -> FindingLifecycleState:
    """F-007 surface: CANDIDATE | REPORTABLE | FALSE_POSITIVE."""
    state = (
        value
        if isinstance(value, FindingLifecycleState)
        else normalize_lifecycle_state(str(value) if value is not None else None)
    )
    if state in _STICKY_STATES:
        return state
    if state in _CANDIDATE_CLASS:
        return FindingLifecycleState.CANDIDATE
    return FindingLifecycleState.CANDIDATE


def can_transition(current: FindingLifecycleState, target: FindingLifecycleState) -> bool:
    """Return True if a transition from ``current`` to ``target`` is allowed.

    Self-transitions (current == target) are always allowed so callers can
    safely re-apply lifecycle inference without raising. CANDIDATE and DETECTED
    are the same surface bucket.
    """
    if current == target:
        return True
    if (
        current in _CANDIDATE_CLASS
        and target in _CANDIDATE_CLASS
        and surface_lifecycle_state(current) == surface_lifecycle_state(target)
    ):
        # Refinement inside CANDIDATE (detected → validated → exploitable).
        if current is FindingLifecycleState.EXPLOITABLE and target in {
            FindingLifecycleState.CANDIDATE,
            FindingLifecycleState.DETECTED,
            FindingLifecycleState.VALIDATED,
        }:
            return False
        if current is FindingLifecycleState.VALIDATED and target in {
            FindingLifecycleState.CANDIDATE,
            FindingLifecycleState.DETECTED,
        }:
            return False
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
    return FindingLifecycleState.CANDIDATE.value


def apply_lifecycle(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        current = item.get("lifecycle_state")
        source = normalize_lifecycle_state(current) if current is not None else None
        if source in _STICKY_STATES:
            item["lifecycle_state"] = source.value
            item["lifecycle_surface"] = source.value
            ticket_raw = item.get("ticket_status") or (
                item.get("status")
                if str(item.get("status") or "").strip().lower() in _TICKET_ONLY
                else None
            )
            item["ticket_status"] = normalize_ticket_status(
                str(ticket_raw) if ticket_raw else "open"
            ).value
            normalized.append(item)
            continue
        inferred = infer_lifecycle_state(item)
        stamped = transition_state(current, inferred)
        item["lifecycle_state"] = stamped
        item["lifecycle_surface"] = surface_lifecycle_state(stamped).value
        ticket_raw = item.get("ticket_status") or (
            item.get("status")
            if str(item.get("status") or "").strip().lower() in _TICKET_ONLY
            else None
        )
        item["ticket_status"] = normalize_ticket_status(
            str(ticket_raw) if ticket_raw else "open"
        ).value
        normalized.append(item)
    return normalized


def is_report_surface(finding: dict[str, Any]) -> bool:
    """True iff this finding may appear in a signed report / PDF.

    Unstamped items already in the reportable bucket are treated as
    REPORTABLE. VALIDATED/EXPLOITABLE refinements cannot skip the
    REPORTABLE promotion.
    """
    if not finding.get("lifecycle_state") and not finding.get("lifecycle_surface"):
        return True
    return (
        surface_lifecycle_state(finding.get("lifecycle_surface") or finding.get("lifecycle_state"))
        is FindingLifecycleState.REPORTABLE
    )


def filter_report_surface(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in apply_lifecycle(findings) if is_report_surface(item)]


__all__ = [
    "FindingLifecycleState",
    "FindingTicketStatus",
    "apply_lifecycle",
    "can_transition",
    "filter_report_surface",
    "infer_lifecycle_state",
    "is_report_surface",
    "normalize_lifecycle_state",
    "normalize_ticket_status",
    "surface_lifecycle_state",
    "transition_state",
]
