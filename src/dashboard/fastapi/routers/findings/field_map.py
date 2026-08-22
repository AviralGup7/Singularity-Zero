"""Canonical finding field aliases between the dashboard API and the console.

The React console historically sent camelCase triage fields
(``assignedTo``, ``falsePositive``, ``kanbanStatus``) while on-disk
payloads and older API clients used snake_case. Updates were silently
dropped because ``ALLOWED_UPDATE_FIELDS`` only listed a subset of
snake_case keys. This module is the single map both read and write
paths use so a field cannot be accepted on one side and discarded on
the other.
"""

from __future__ import annotations

from typing import Any

# Frontend camelCase → persisted snake_case
CAMEL_TO_SNAKE: dict[str, str] = {
    "assignedTo": "assignee",
    "assignee": "assignee",
    "falsePositive": "false_positive",
    "false_positive": "false_positive",
    "fpStatus": "fp_status",
    "fp_status": "fp_status",
    "fpJustification": "fp_justification",
    "fp_justification": "fp_justification",
    "kanbanStatus": "kanban_status",
    "kanban_status": "kanban_status",
    "lifecycleState": "lifecycle_state",
    "lifecycle_state": "lifecycle_state",
    "bountyValue": "bounty_value",
    "bounty_value": "bounty_value",
    "bountyCurrency": "bounty_currency",
    "bounty_currency": "bounty_currency",
    "bountySource": "bounty_source",
    "bounty_source": "bounty_source",
    "alreadyReported": "already_reported",
    "already_reported": "already_reported",
    "scopeMatch": "scope_match",
    "scope_match": "scope_match",
    "duplicates": "duplicates",
    "notes": "notes",
    "tags": "tags",
    "status": "status",
    "severity": "severity",
    "decision": "decision",
    "title": "title",
    "description": "description",
    "remediation_status": "remediation_status",
    "remediation_notes": "remediation_notes",
    "remediationStatus": "remediation_status",
    "remediationNotes": "remediation_notes",
}

# Persisted snake_case → frontend camelCase (only fields the console reads)
SNAKE_TO_CAMEL: dict[str, str] = {
    "assignee": "assignedTo",
    "false_positive": "falsePositive",
    "fp_status": "fpStatus",
    "fp_justification": "fpJustification",
    "kanban_status": "kanbanStatus",
    "bounty_value": "bounty_value",
    "bounty_currency": "bounty_currency",
    "bounty_source": "bounty_source",
    "already_reported": "already_reported",
    "scope_match": "scope_match",
}

# Values the console writes for ``status`` vs values stored on disk.
# The console filter chips use open/closed/accepted; older payloads used
# active/resolved/ignored. Keep both readable.
STATUS_TO_STORAGE: dict[str, str] = {
    "open": "open",
    "active": "open",
    "new": "open",
    "closed": "closed",
    "resolved": "closed",
    "accepted": "accepted",
    "ignored": "accepted",
    "false_positive": "false_positive",
    "false-positive": "false_positive",
    "fp": "false_positive",
}

STATUS_TO_API: dict[str, str] = {
    "open": "open",
    "active": "open",
    "new": "open",
    "closed": "closed",
    "resolved": "closed",
    "accepted": "accepted",
    "ignored": "accepted",
    "false_positive": "false_positive",
    "false-positive": "false_positive",
}

ALLOWED_UPDATE_FIELDS: frozenset[str] = frozenset(
    {
        "status",
        "severity",
        "decision",
        "notes",
        "lifecycle_state",
        "assignee",
        "tags",
        "false_positive",
        "fp_status",
        "fp_justification",
        "kanban_status",
        "duplicates",
        "bounty_value",
        "bounty_currency",
        "bounty_source",
        "already_reported",
        "scope_match",
        "remediation_status",
        "remediation_notes",
        "title",
        "description",
    }
)

ALLOWED_BULK_FIELDS: frozenset[str] = frozenset(
    {
        "status",
        "severity",
        "decision",
        "notes",
        "lifecycle_state",
        "assignee",
        "tags",
        "false_positive",
        "fp_status",
        "fp_justification",
        "kanban_status",
        "duplicates",
        "_deleted",
    }
)


def canonicalize_status(value: Any, *, for_api: bool = True) -> str:
    raw = str(value or "").strip().lower()
    table = STATUS_TO_API if for_api else STATUS_TO_STORAGE
    return table.get(raw, "open" if for_api else "open")


def map_update_payload(raw: dict[str, Any], *, bulk: bool = False) -> dict[str, Any]:
    """Translate a console update body into persisted field names.

    Unknown keys are ignored. ``id`` / ``finding_id`` / ``ids`` never write.
    """
    allowed = ALLOWED_BULK_FIELDS if bulk else ALLOWED_UPDATE_FIELDS
    mapped: dict[str, Any] = {}
    for key, value in raw.items():
        if key in {"id", "finding_id", "ids"}:
            continue
        snake = CAMEL_TO_SNAKE.get(key)
        if snake is None:
            continue
        if snake == "_deleted" and not bulk:
            continue
        if snake not in allowed and snake != "_deleted":
            continue
        if snake == "status":
            mapped[snake] = canonicalize_status(value, for_api=False)
        elif snake == "false_positive":
            mapped[snake] = bool(value)
            if value and "fp_status" not in mapped:
                mapped["fp_status"] = "approved"
        else:
            mapped[snake] = value
    return mapped


def project_finding_aliases(finding: dict[str, Any]) -> dict[str, Any]:
    """Expose both snake_case and camelCase so older and newer consoles work."""
    projected = dict(finding)
    if "assignee" in projected and "assignedTo" not in projected:
        projected["assignedTo"] = projected.get("assignee")
    if projected.get("assignedTo") and not projected.get("assignee"):
        projected["assignee"] = projected["assignedTo"]
    if "false_positive" in projected and "falsePositive" not in projected:
        projected["falsePositive"] = bool(projected.get("false_positive"))
    if "falsePositive" in projected and "false_positive" not in projected:
        projected["false_positive"] = bool(projected.get("falsePositive"))
    if "fp_status" in projected and "fpStatus" not in projected:
        projected["fpStatus"] = projected.get("fp_status")
    if "fp_justification" in projected and "fpJustification" not in projected:
        projected["fpJustification"] = projected.get("fp_justification")
    if "kanban_status" in projected and "kanbanStatus" not in projected:
        projected["kanbanStatus"] = projected.get("kanban_status")
    status = canonicalize_status(projected.get("status"), for_api=True)
    if projected.get("false_positive") or projected.get("falsePositive"):
        if status == "open":
            status = "false_positive"
    projected["status"] = status
    return projected
