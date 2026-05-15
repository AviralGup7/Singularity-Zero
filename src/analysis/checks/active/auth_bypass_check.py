"""Auth Bypass Active Check - Detection plugin for authentication bypass testing.

Registers as an active detection plugin that runs JWT stripping, cookie
manipulation, and parameter-based auth bypass probes. Produces findings
with category "auth_bypass".
"""

import logging
from typing import Any

from src.analysis.active.auth_bypass import (
    probe_auth_bypass_patterns,
    probe_cookie_manipulation,
    probe_jwt_stripping,
)
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.helpers.scoring import severity_score
from src.analysis.passive.runtime import ResponseCache
from src.analysis.plugins import AnalysisPluginSpec

logger = logging.getLogger(__name__)

AUTH_BYPASS_CHECK_SPEC = AnalysisPluginSpec(
    key="auth_bypass_check",
    label="Auth Bypass Active Check",
    description="Actively test endpoints for authentication bypass via JWT stripping, cookie manipulation, and parameter injection.",
    group="active",
    slug="auth_bypass",
    enabled_by_default=True,
)

_AUTH_BYPASS_SEVERITY = {
    "jwt_stripping_bypass": "critical",
    "jwt_stripping_partial_access": "high",
    "cookie_deleted_bypass": "critical",
    "cookie_empty_bypass": "critical",
    "cookie_modified_bypass": "high",
    "cookie_fixation_indicator": "medium",
    "param_bypass_admin_true": "high",
    "param_bypass_role_admin": "critical",
    "param_bypass_debug": "medium",
    "param_bypass_token_null": "high",
    "param_body_bypass": "critical",
}

_AUTH_BYPASS_CONFIDENCE = {
    "jwt_stripping_bypass": 0.90,
    "jwt_stripping_partial_access": 0.75,
    "cookie_deleted_bypass": 0.88,
    "cookie_empty_bypass": 0.85,
    "cookie_modified_bypass": 0.82,
    "cookie_fixation_indicator": 0.70,
    "param_bypass_admin_true": 0.80,
    "param_bypass_role_admin": 0.85,
    "param_bypass_debug": 0.65,
    "param_bypass_token_null": 0.78,
    "param_body_bypass": 0.84,
}


def _build_finding(
    url: str,
    severity: str,
    title: str,
    category: str,
    signals: list[str],
    evidence: dict[str, Any],
    explanation: str,
    status_code: int | None = None,
) -> dict[str, Any]:
    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "status_code": status_code,
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": _AUTH_BYPASS_CONFIDENCE.get(severity, 0.6),
        "signals": signals,
        "evidence": evidence,
        "explanation": explanation,
        "score": severity_score(severity),
    }


def _merge_probe_findings(
    probe_results: list[dict[str, Any]],
    probe_type: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for probe in probe_results:
        url = str(probe.get("url", "")).strip()
        if not url:
            continue
        issues = probe.get("issues", [])
        if not issues:
            continue
        severity = "info"
        for issue in issues:
            issue_sev = _AUTH_BYPASS_SEVERITY.get(issue, "medium")
            if severity_score(issue_sev) > severity_score(severity):
                severity = issue_sev
        title = f"Auth bypass detected ({probe_type}): {url}"
        explanation = (
            f"Endpoint '{url}' showed authentication bypass indicators "
            f"during {probe_type} probing. Issues: {', '.join(issues)}. "
            f"Original status: {probe.get('original_status', 'N/A')}, "
            f"Probe status: {probe.get('stripped_status', probe.get('status', 'N/A'))}."
        )
        finding = _build_finding(
            url=url,
            severity=severity,
            title=title,
            category="auth_bypass",
            signals=issues,
            evidence={
                "probe_type": probe_type,
                "issues": issues,
                "probes": probe.get("probes", []),
                "original_status": probe.get("original_status"),
                "probe_status": probe.get(
                    "stripped_status",
                    probe.get("status"),
                ),
            },
            explanation=explanation,
            status_code=probe.get("stripped_status", probe.get("status")),
        )
        findings.append(finding)
    return findings


def auth_bypass_check(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 15,
) -> list[dict[str, Any]]:
    """Run auth bypass active probes and return standardized findings.

    Executes JWT stripping, cookie manipulation, and auth bypass parameter
    probes against the provided URLs. Merges results into a unified list
    of findings with category "auth_bypass".

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of finding dicts with category "auth_bypass".
    """
    findings: list[dict[str, Any]] = []

    logger.info("Running auth_bypass_check on %d URLs", len(priority_urls))

    jwt_results = probe_jwt_stripping(priority_urls, response_cache, limit=limit)
    cookie_results = probe_cookie_manipulation(priority_urls, response_cache, limit=limit)
    bypass_results = probe_auth_bypass_patterns(priority_urls, response_cache, limit=limit)

    findings.extend(_merge_probe_findings(jwt_results, "jwt_stripping"))
    findings.extend(_merge_probe_findings(cookie_results, "cookie_manipulation"))
    findings.extend(_merge_probe_findings(bypass_results, "auth_bypass_patterns"))

    findings.sort(key=lambda item: (-item["score"], -item["confidence"], item["url"]))
    return findings[:limit]
