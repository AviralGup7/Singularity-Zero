"""Score findings for validation priority."""

from __future__ import annotations

from typing import Any

_SEV = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5}


def finding_priority(finding: dict[str, Any]) -> float:
    severity = str(finding.get("severity") or "info").lower()
    confidence = float(finding.get("confidence") or 0.5)
    base = _SEV.get(severity, 10)
    url = str(finding.get("url") or "")
    bonus = 0.0
    if any(token in url.lower() for token in ("admin", "auth", "login", "internal")):
        bonus += 12
    if finding.get("authenticated"):
        bonus += 8
    return round(base * confidence + bonus, 2)


def order_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=finding_priority, reverse=True)


def top_n(findings: list[dict[str, Any]], n: int = 10) -> list[dict[str, Any]]:
    return order_findings(findings)[: max(0, n)]
