"""Result validators and signature checkers for JWT security tests."""

from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

ATTACK_SEVERITY_MAP = {
    "alg_none_bypass_auth_bypass": "critical",
    "alg_confusion_rs256_to_hs256_bypass": "critical",
    "kid_traversal_auth_bypass": "high",
    "kid_traversal_file_content_leak": "critical",
    "weak_secret_accepted": "critical",
    "weak_secret_admin_reflection": "high",
    "lifetime_expired_token_bypass": "high",
    "lifetime_expired_token_accepted": "high",
    "lifetime_far_future_expiry": "medium",
    "lifetime_missing_exp": "medium",
    "jku_injection_auth_bypass": "high",
}


def collect_findings(
    attacks: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collect individual findings from all attack results.

    Args:
        attacks: Dict of attack_name -> attack_result dict.

    Returns:
        List of individual finding dicts with attack name, finding type,
        status codes, and auth header information.
    """
    findings: list[dict[str, Any]] = []
    for name, result in attacks.items():
        if result.get("vulnerable"):
            for detail in result.get("details", []):
                findings.append(
                    {
                        "attack": name,
                        "finding": detail.get("finding", name),
                        "status_code": detail.get("status_code"),
                        "original_status": detail.get("original_status"),
                        "auth_header": detail.get("auth_header"),
                    }
                )
    return findings


def determine_severity(vulnerable_count: int) -> str:
    """Determine overall severity from the number of vulnerable attacks.

    Args:
        vulnerable_count: Number of attacks that succeeded.

    Returns:
        Severity string: critical, high, medium, or info.
    """
    if vulnerable_count >= 3:
        return "critical"
    if vulnerable_count >= 2:
        return "high"
    if vulnerable_count >= 1:
        return "medium"
    return "info"


def validate_attack_result(result: dict[str, Any]) -> bool:
    """Validate that an attack result is well-formed.

    Args:
        result: Attack result dict.

    Returns:
        True if the result has expected fields.
    """
    return isinstance(result, dict) and "attack" in result and "vulnerable" in result
