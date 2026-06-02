"""Control maturity scoring for regulatory compliance reporting.

Defines maturity levels for security controls based on the presence
and severity of unresolved findings.
"""

from enum import IntEnum, StrEnum
from typing import Any

# Import unified maturity from the core models
try:
    from src.core.models.grc import ControlMaturity
except ImportError:

    class ControlMaturity(StrEnum):  # type: ignore[no-redef]
        """Maturity levels for a security control."""

        PASS = "PASS"  # noqa: S105
        PARTIAL = "PARTIAL"
        AT_RISK = "AT_RISK"
        FAIL = "FAIL"
        UNKNOWN = "UNKNOWN"


class MaturityScore(IntEnum):
    """Integer scores for maturity levels (higher is better)."""

    FAIL = 0
    AT_RISK = 1
    PARTIAL = 2
    PASS = 3
    UNKNOWN = -1


def calculate_control_maturity(
    findings: list[dict[str, Any]], sla_breached: bool = False
) -> ControlMaturity:
    """Calculate the maturity level for a set of findings mapped to a control.

    Args:
        findings: List of finding dictionaries associated with a control.
        sla_breached: Whether any associated SLA has been breached.

    Returns:
        ControlMaturity level.
    """
    if sla_breached:
        return ControlMaturity.FAIL

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


def calculate_overall_grc_score(control_maturities: dict[str, ControlMaturity]) -> dict[str, Any]:
    """Calculate the overall GRC maturity score and determine Pass/Fail band status.

    Args:
        control_maturities: Mapping of control IDs to their individual maturities.

    Returns:
        Dictionary containing overall_score (0.0 to 100.0), band ("PASS", "PARTIAL", "FAIL"),
        and detailed stats.
    """
    if not control_maturities:
        return {
            "overall_score": 100.0,
            "band": "PASS",
            "evaluated_controls_count": 0,
            "pass_count": 0,
            "fail_count": 0,
            "partial_count": 0,
        }

    # Assign weights to maturities: PASS=100, PARTIAL=70, AT_RISK=40, FAIL=0
    maturity_weights = {
        ControlMaturity.PASS: 100.0,
        ControlMaturity.PARTIAL: 70.0,
        ControlMaturity.AT_RISK: 40.0,
        ControlMaturity.FAIL: 0.0,
        ControlMaturity.UNKNOWN: 100.0,  # Unknown is treated as neutral/pass for scoring
    }

    total_weight = 0.0
    evaluated_count = 0
    pass_count = 0
    fail_count = 0
    partial_count = 0

    for control_id, maturity in control_maturities.items():
        if maturity == ControlMaturity.UNKNOWN:
            continue
        evaluated_count += 1
        total_weight += maturity_weights.get(maturity, 100.0)
        if maturity == ControlMaturity.PASS:
            pass_count += 1
        elif maturity in (ControlMaturity.FAIL, ControlMaturity.AT_RISK):
            fail_count += 1
        elif maturity == ControlMaturity.PARTIAL:
            partial_count += 1

    if evaluated_count == 0:
        return {
            "overall_score": 100.0,
            "band": "PASS",
            "evaluated_controls_count": 0,
            "pass_count": 0,
            "fail_count": 0,
            "partial_count": 0,
        }

    overall_score = total_weight / evaluated_count

    # Define Bands:
    # FAIL: overall_score < 50.0 or any critical FAIL controls
    # PASS: overall_score >= 85.0 and zero FAIL/AT_RISK controls
    # PARTIAL: fallback intermediate state
    if any(m == ControlMaturity.FAIL for m in control_maturities.values()):
        band = "FAIL"
    elif overall_score < 50.0:
        band = "FAIL"
    elif overall_score >= 85.0 and not any(
        m in (ControlMaturity.FAIL, ControlMaturity.AT_RISK) for m in control_maturities.values()
    ):
        band = "PASS"
    else:
        band = "PARTIAL"

    return {
        "overall_score": round(overall_score, 2),
        "band": band,
        "evaluated_controls_count": evaluated_count,
        "pass_count": pass_count,
        "partial_count": partial_count,
        "fail_count": fail_count,
    }
