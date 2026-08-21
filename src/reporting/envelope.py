"""Build submission envelopes from console findings."""

from __future__ import annotations

from typing import Any

from src.reporting.platforms.base import SubmissionEnvelope, to_envelope


SEVERITY_ALIASES = {
    "crit": "critical",
    "sev-critical": "critical",
    "sev-high": "high",
    "sev-medium": "medium",
    "sev-low": "low",
    "informational": "info",
}


def normalize_severity(raw: object) -> str:
    value = str(raw or "medium").strip().lower()
    return SEVERITY_ALIASES.get(value, value if value in {"critical", "high", "medium", "low", "info"} else "medium")


def finding_to_envelope(finding: dict[str, Any], *, draft: bool = True) -> SubmissionEnvelope:
    payload = dict(finding)
    payload["severity"] = normalize_severity(finding.get("severity"))
    payload["draft"] = draft
    if not payload.get("title"):
        payload["title"] = str(finding.get("id") or "Security finding")
    return to_envelope(payload)


def batch_envelopes(findings: list[dict[str, Any]], *, min_severity: str = "low") -> list[SubmissionEnvelope]:
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    floor = rank.get(normalize_severity(min_severity), 1)
    envelopes: list[SubmissionEnvelope] = []
    for finding in findings:
        envelope = finding_to_envelope(finding)
        if rank.get(envelope.severity, 0) < floor:
            continue
        envelopes.append(envelope)
    return envelopes
