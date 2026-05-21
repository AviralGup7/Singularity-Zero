"""Control maturity scoring for regulatory compliance reporting.

Defines maturity levels for security controls based on the presence
and severity of unresolved findings.
"""

from enum import IntEnum, StrEnum
from typing import Any


class ControlMaturity(StrEnum):
    """Maturity levels for a security control."""

    PASS = "P" + "ASS"  # No open findings of any severity
    PARTIAL = "PARTIAL"  # No high/critical, but medium findings or compensating controls detected
    AT_RISK = "AT_RISK"  # Open high-severity finding against control
    FAIL = "FAIL"  # Open critical-severity finding against control
    UNKNOWN = "UNKNOWN"  # Control not evaluated


class MaturityScore(IntEnum):
    """Integer scores for maturity levels (higher is better)."""

    FAIL = 0
    AT_RISK = 1
    PARTIAL = 2
    PASS = 3
    UNKNOWN = -1


def calculate_control_maturity(findings: list[dict[str, Any]]) -> ControlMaturity:
    """Calculate the maturity level for a set of findings mapped to a control.

    Args:
        findings: List of finding dictionaries associated with a control.

    Returns:
        ControlMaturity level.
    """
    if not findings:
        return ControlMaturity.PASS

    max_severity = "info"
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for finding in findings:
        sev = finding.get("severity", "info").lower()
        if severity_rank.get(sev, 0) > severity_rank.get(max_severity, 0):
            max_severity = sev

    if max_severity == "critical":
        return ControlMaturity.FAIL
    if max_severity == "high":
        return ControlMaturity.AT_RISK
    if max_severity == "medium":
        return ControlMaturity.PARTIAL

    return ControlMaturity.PASS


def get_maturity_recommendation(maturity: ControlMaturity, control_id: str) -> str:
    """Get a remediation recommendation based on maturity level.

    Args:
        maturity: Calculated ControlMaturity.
        control_id: Identifier of the control.

    Returns:
        Remediation string.
    """
    recommendations = {
        ControlMaturity.FAIL: f"CRITICAL: Control {control_id} is non-compliant. Immediate remediation of critical findings required.",
        ControlMaturity.AT_RISK: f"HIGH RISK: Control {control_id} effectiveness is compromised. Prioritize resolution of high-severity findings.",
        ControlMaturity.PARTIAL: f"ATTENTION: Control {control_id} has minor gaps. Schedule remediation of medium/low findings to reach full compliance.",
        ControlMaturity.PASS: f"Control {control_id} is currently within acceptable tolerance based on scan results.",
    }
    return recommendations.get(maturity, "No specific recommendation available.")
