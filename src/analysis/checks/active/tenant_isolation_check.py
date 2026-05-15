"""Tenant Isolation Check - Active detection plugin for multi-tenant isolation testing.

Detects multi-tenant applications and runs tenant isolation, vertical escalation,
and cross-tenant data access tests. Produces findings with category "tenant_isolation".
"""

import logging
from typing import Any

from src.analysis.active.tenant_isolation import (
    detect_tenant_parameters,
    run_tenant_isolation_probes,
)
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.helpers.scoring import severity_score
from src.analysis.plugins import AnalysisPluginSpec

logger = logging.getLogger(__name__)

TENANT_ISOLATION_CHECK_SPEC = AnalysisPluginSpec(
    key="tenant_isolation_check",
    label="Tenant Isolation Check",
    description="Detect multi-tenant applications and test tenant isolation for horizontal and vertical privilege escalation vulnerabilities.",
    group="active",
    slug="tenant_isolation",
    enabled_by_default=True,
)

_TENANT_SEVERITY = {
    "tenant_isolation_auth_bypass": "critical",
    "vertical_escalation_auth_bypass": "critical",
    "cross_tenant_unauthorized_access": "critical",
    "tenant_field_changed": "high",
    "vertical_escalation_admin_response": "high",
    "vertical_escalation_new_admin_fields": "high",
    "tenant_data_ids_differ": "medium",
    "tenant_keys_changed": "medium",
    "cross_tenant_access": "medium",
    "tenant_body_length_diff": "low",
}

_TENANT_CONFIDENCE = {
    "critical": 0.80,
    "high": 0.72,
    "medium": 0.60,
    "low": 0.45,
    "info": 0.30,
}


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
        "confidence": _TENANT_CONFIDENCE.get(severity, 0.6),
        "signals": signals,
        "evidence": evidence,
        "explanation": explanation,
        "score": score_map.get(severity, 20),
    }


def _merge_probe_results(
    probe_results: list[dict[str, Any]],
    probe_type: str,
    tenant_params_info: dict[str, Any],
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
            issue_sev = _TENANT_SEVERITY.get(issue, "medium")
            if severity_score(issue_sev) > severity_score(severity):
                severity = issue_sev
        title = f"Tenant isolation issue ({probe_type}): {url}"
        explanation = (
            f"Endpoint '{url}' showed tenant isolation indicators "
            f"during {probe_type} probing. Issues: {', '.join(issues)}. "
            f"Tenant parameters detected: {', '.join(tenant_params_info.get('tenant_params', []))}."
        )
        finding = _build_finding(
            url=url,
            severity=severity,
            title=title,
            signals=issues,
            evidence={
                "probe_type": probe_type,
                "issues": issues,
                "tenant_parameters": tenant_params_info,
                "probes": probe.get("probes", []),
            },
            explanation=explanation,
            status_code=probe.get("status_code"),
        )
        findings.append(finding)
    return findings


def tenant_isolation_check(
    priority_urls: list[dict[str, Any]],
    response_cache: Any = None,
    limit: int = 15,
) -> list[dict[str, Any]]:
    """Run tenant isolation active probes and return standardized findings.

    Detects multi-tenant applications by scanning URLs and responses for
    tenant-related parameters, then performs isolation, vertical escalation,
    and cross-tenant data access tests.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests and retrieving baselines.
        limit: Maximum number of findings to return.

    Returns:
        List of finding dicts with category "tenant_isolation".
    """
    findings: list[dict[str, Any]] = []

    logger.info("Running tenant_isolation_check on %d URLs", len(priority_urls))

    urls_for_detection = [
        str(item.get("url", "")).strip() for item in priority_urls if item.get("url")
    ]

    responses_for_detection = []
    if response_cache is not None:
        for item in priority_urls[:50]:
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            try:
                resp = response_cache.get(url)
                if resp:
                    resp["url"] = url
                    responses_for_detection.append(resp)
            except Exception:
                logger.warning("Detection probe failed for an endpoint")
                pass

    detection = detect_tenant_parameters(urls_for_detection, responses_for_detection)
    multi_tenant = detection.get("multi_tenant_detected", False)
    tenant_params_list = detection.get("tenant_params", [])

    if not tenant_params_list and not multi_tenant:
        logger.info("No tenant parameters or multi-tenant indicators detected, skipping")
        return findings

    logger.info(
        "Multi-tenant detected: %s, Tenant params: %s",
        multi_tenant,
        tenant_params_list,
    )

    config = {
        "max_urls_to_test": limit,
        "max_findings": limit,
        "test_types": ["isolation", "vertical", "cross_tenant"],
    }

    probe_results = run_tenant_isolation_probes(
        urls=urls_for_detection,
        responses=responses_for_detection,
        session=None,
        config=config,
    )

    probe_findings = probe_results.get("findings", [])
    findings.extend(probe_findings)

    findings.sort(
        key=lambda item: (-item.get("score", 0), -item.get("confidence", 0), item.get("url", ""))
    )
    return findings[:limit]
