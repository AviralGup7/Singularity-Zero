"""Adapters that expose leftover analysis modules as optional plugins.

Each runner matches an ``input_kind`` contract so operators can enable the
capability from the check catalog without deleting the richer class APIs.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _as_url(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("url") or "")
    return str(item or "")


def secrets_response_scanner(responses: list[dict[str, Any]], limit: int = 80) -> list[dict[str, Any]]:
    from src.analysis.checks.passive.secrets_scanner import scan_response

    findings: list[dict[str, Any]] = []
    for row in responses[: max(1, limit)]:
        url = _as_url(row)
        if not url:
            continue
        try:
            hits = scan_response(
                url,
                headers=row.get("headers") if isinstance(row.get("headers"), dict) else None,
                body=row.get("body_text") or row.get("body"),
            )
        except Exception as exc:
            logger.debug("secrets_response_scanner failed for %s: %s", url, exc)
            continue
        for hit in hits:
            payload = hit.to_dict()
            payload.setdefault("title", hit.secret_type)
            payload.setdefault("severity", "high" if hit.confidence == "high" else "medium")
            findings.append(payload)
    return findings


def passive_mass_assignment_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    from src.analysis.passive.detectors.detector_mass_assignment import (
        mass_assignment_detector,
    )

    return mass_assignment_detector(urls, responses, limit=limit)


def csp_bypass_probe(responses: list[dict[str, Any]], limit: int = 40) -> list[dict[str, Any]]:
    from src.analysis.active.csp_bypass import CSPBypassProbe

    probe = CSPBypassProbe()
    findings: list[dict[str, Any]] = []
    for row in responses[: max(1, limit)]:
        url = _as_url(row)
        if not url:
            continue
        try:
            policy = probe.extract_csp(row)
            unsafe = probe.test_unsafe_inline(policy)
            nonce = probe.test_nonce_bruteforce(policy)
            base = probe.test_base_uri_manipulation(policy)
        except Exception as exc:
            logger.debug("csp_bypass_probe failed for %s: %s", url, exc)
            continue
        issues = []
        if unsafe.get("unsafe_inline"):
            issues.append("csp_unsafe_inline")
        if nonce.get("nonce_bruteforce_possible"):
            issues.append("csp_weak_nonce")
        if base.get("base_uri_allows_any"):
            issues.append("csp_permissive_base_uri")
        if issues:
            findings.append(
                {
                    "url": url,
                    "title": "CSP bypass surface",
                    "severity": "medium",
                    "issues": issues,
                    "evidence": {"unsafe": unsafe, "nonce": nonce, "base_uri": base},
                }
            )
    return findings


def api_security_assessor(urls: set[str], responses: list[dict[str, Any]], limit: int = 40) -> list[dict[str, Any]]:
    from src.analysis.checks.active.api_security_assessor import APISecurityAssessor

    endpoints: list[dict[str, Any]] = []
    for url in list(urls)[: max(1, limit)]:
        endpoints.append({"url": url, "method": "GET"})
    for row in responses[: max(1, limit)]:
        url = _as_url(row)
        if url:
            endpoints.append({"url": url, "method": str(row.get("method") or "GET")})
    try:
        raw = APISecurityAssessor().assess_endpoints(endpoints)
    except Exception as exc:
        logger.debug("api_security_assessor failed: %s", exc)
        return []
    findings: list[dict[str, Any]] = []
    for item in raw:
        payload = item.__dict__.copy() if hasattr(item, "__dict__") else dict(item)  # type: ignore[arg-type]
        payload.setdefault("url", payload.get("endpoint") or "")
        payload.setdefault("title", payload.get("message") or payload.get("check") or "API finding")
        findings.append(payload)
    return findings


def differential_logic_prober(responses: list[dict[str, Any]], limit: int = 40) -> list[dict[str, Any]]:
    from src.analysis.intelligence.differential_prober import apply_differential_analysis

    return apply_differential_analysis(responses[: max(1, limit)])


def semantic_finding_dedup(bulk_findings: list[dict[str, Any]], limit: int = 200) -> list[dict[str, Any]]:
    from src.analysis.intelligence.semantic_dedup import apply_frontier_deduplication

    return apply_frontier_deduplication(bulk_findings[: max(1, limit)])


def graphql_batch_attack_probe(
    priority_urls: list[Any],
    response_cache: Any = None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    from src.analysis.active.graphql_batch import GraphQLBatchAttack

    findings: list[dict[str, Any]] = []
    attacker = GraphQLBatchAttack()
    for item in list(priority_urls)[: max(1, limit)]:
        url = _as_url(item)
        if not url or "graphql" not in url.lower():
            continue
        try:
            run = getattr(attacker, "run", None) or getattr(attacker, "attack", None)
            result = run(url) if callable(run) else None
        except Exception as exc:
            logger.debug("graphql_batch_attack_probe failed for %s: %s", url, exc)
            continue
        if isinstance(result, list):
            for row in result:
                if isinstance(row, dict):
                    row.setdefault("url", url)
                    findings.append(row)
        elif result:
            findings.append({"url": url, "title": "GraphQL batch attack", "evidence": result})
    return findings
