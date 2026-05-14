"""Finding builder for tenant isolation test results."""

from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature


def _build_finding(
    url: str,
    severity: str,
    title: str,
    signals: list[str],
    evidence: dict[str, Any],
    explanation: str,
    status_code: int | None = None,
) -> dict[str, Any]:
    score_map = {"critical": 100, "high": 80, "medium": 50, "low": 20, "info": 5}
    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "status_code": status_code,
        "category": "tenant_isolation",
        "title": title,
        "severity": severity,
        "confidence": 0.78
        if severity in ("critical", "high")
        else 0.62
        if severity == "medium"
        else 0.45,
        "signals": signals,
        "evidence": evidence,
        "explanation": explanation,
        "score": score_map.get(severity, 20),
    }
