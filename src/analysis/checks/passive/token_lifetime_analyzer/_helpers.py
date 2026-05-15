"""Helper functions for token lifetime analysis."""

import base64
import json
from typing import Any


def decode_jwt_segment(segment: str) -> dict[str, Any] | None:
    """Decode a base64url-encoded JWT segment."""
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(segment)
        result = json.loads(decoded)
        return result if isinstance(result, dict) else None
    except Exception:
        return None


def severity_score(severity: str) -> int:
    """Map a severity string to a numeric score."""
    mapping = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}
    return mapping.get(severity.lower(), 10)


def compute_confidence(issues: list[str]) -> float:
    """Compute confidence score from detected issues."""
    if not issues:
        return 0.3
    confidence_map = {
        "jwt_alg_none": 0.95,
        "jwt_no_expiration": 0.85,
        "jwt_long_expiration": 0.80,
        "jwt_missing_iat": 0.70,
        "jwt_missing_nbf": 0.60,
        "jwt_weak_algorithm": 0.75,
        "token_in_url_parameter": 0.90,
        "token_referer_risk": 0.85,
        "token_not_rotated": 0.80,
        "cookie_no_expiration": 0.60,
        "cookie_long_max_age": 0.70,
        "api_key_reused": 0.75,
        "api_key_in_frontend": 0.85,
        "token_leak_in_body": 0.70,
    }
    max_conf = max((confidence_map.get(issue, 0.4) for issue in issues), default=0.3)
    bonus = min(0.05, len(issues) * 0.01)
    return round(min(max_conf + bonus, 0.98), 2)


def determine_severity(issues: list[str]) -> str:
    """Determine the highest severity from detected issues."""
    severity_map = {
        "jwt_alg_none": "critical",
        "jwt_no_expiration": "high",
        "jwt_long_expiration": "high",
        "jwt_missing_iat": "medium",
        "jwt_missing_nbf": "low",
        "jwt_weak_algorithm": "medium",
        "token_in_url_parameter": "high",
        "token_referer_risk": "high",
        "token_not_rotated": "high",
        "cookie_no_expiration": "low",
        "cookie_long_max_age": "medium",
        "api_key_reused": "medium",
        "api_key_in_frontend": "high",
        "token_leak_in_body": "medium",
    }
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    if not issues:
        return "low"
    return max(issues, key=lambda i: severity_order.get(severity_map.get(i, "low"), 0))
