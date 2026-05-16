"""Access Control Analyzer - Automated authorization bypass detection.

Inspired by Autorize Burp extension but fully automated.
Tests endpoints with different auth contexts and compares responses.
Produces findings with category "access_control_bypass".
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from src.analysis.automation.access_control import AccessControlAnalyzer, EnforcementResult
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.helpers.scoring import severity_score
from src.analysis.passive.runtime import ResponseCache

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[int, int, str], Awaitable[None] | None]

_SEVERITY_MAP = {
    "bypassed": "critical",
    "partial": "high",
    "enforced": "info",
}

_CONFIDENCE_MAP = {
    "bypassed": 0.92,
    "partial": 0.75,
    "enforced": 0.95,
}


def _coerce_limit(limit: object) -> int:
    from typing import cast, Any
    try:
        parsed = int(cast(Any, limit))
    except (TypeError, ValueError) as exc:
        logger.debug("Ignoring %s: %s", type(exc).__name__, exc)
        return 20
    return max(1, parsed)


def _build_finding(
    result: EnforcementResult,
) -> dict[str, Any]:
    severity = _SEVERITY_MAP.get(result.result, "medium")
    confidence = _CONFIDENCE_MAP.get(result.result, 0.6)

    if result.test_context == "no_auth":
        title = f"Authorization bypass: {result.endpoint} accessible without authentication"
        category = "auth_bypass_no_auth"
    else:
        title = f"Authorization bypass: {result.endpoint} accessible with invalid token"
        category = "auth_bypass_invalid_token"

    explanation = (
        f"Endpoint '{result.endpoint}' ({result.method}) returned "
        f"status {result.test_status} when tested with {result.test_context}. "
        f"Original status was {result.original_status}. "
        f"Response lengths: {result.original_length} vs {result.test_length} bytes. "
        f"Details: {result.details}"
    )

    return {
        "url": result.endpoint,
        "endpoint_key": endpoint_signature(result.endpoint),
        "endpoint_base_key": endpoint_base_key(result.endpoint),
        "endpoint_type": classify_endpoint(result.endpoint),
        "method": result.method,
        "status_code": result.test_status,
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "signals": [f"access_control_{result.result}", f"context_{result.test_context}"],
        "evidence": {
            "original_status": result.original_status,
            "test_status": result.test_status,
            "original_length": result.original_length,
            "test_length": result.test_length,
            "test_context": result.test_context,
            "result": result.result,
            "details": result.details,
        },
        "explanation": explanation,
        "score": severity_score(severity),
    }


def access_control_analyzer(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Run automated authorization bypass detection and return findings.

    Tests each endpoint with no auth headers and with an invalid token,
    comparing responses to detect authorization enforcement failures.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of finding dicts with access control bypass categories.
    """
    logger.info("Running access_control_analyzer on %d URLs", len(priority_urls))

    endpoints = []
    for url_entry in priority_urls:
        url = url_entry.get("url", "")
        if not url:
            continue
        endpoints.append(
            {
                "url": url,
                "method": url_entry.get("method", "GET"),
                "response": url_entry.get("response", {}),
                "request_headers": url_entry.get("request_headers", {}),
            }
        )

    if not endpoints:
        return []

    return analyze_access_control(endpoints, response_cache=response_cache, limit=limit)


def _build_findings_from_results(
    results: list[EnforcementResult],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in results:
        if result.result in ("bypassed", "partial"):
            findings.append(_build_finding(result))

    findings.sort(key=lambda item: (-item["score"], -item["confidence"], item["url"]))
    return findings[:limit]


async def analyze_access_control_async(
    endpoints: list[dict[str, Any]],
    response_cache: ResponseCache | None = None,
    limit: int = 20,
    progress_callback: ProgressCallback | None = None,
) -> list[dict[str, Any]]:
    """Canonical async access-control entrypoint.

    Access-control analysis performs HTTP I/O and should be consumed asynchronously.
    """
    if not endpoints:
        return []

    analyzer = AccessControlAnalyzer(http_client=response_cache)
    results = await analyzer.analyze_endpoints(
        endpoints,
        progress_callback=progress_callback,
    )
    return _build_findings_from_results(results, limit=_coerce_limit(limit))


def analyze_access_control(
    endpoints: list[dict[str, Any]],
    response_cache: ResponseCache | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Compatibility wrapper for access control testing entrypoints.

    This function is imported by pipeline stages and keeps the older contract
    stable while delegating to the modern AccessControlAnalyzer class.
    """
    if not endpoints:
        return []

    try:
        running_loop = asyncio.get_running_loop()
    except RuntimeError:
        running_loop = None

    if running_loop is not None and running_loop.is_running():
        raise RuntimeError(
            "analyze_access_control cannot be called from a running event loop; "
            "use 'await analyze_access_control_async(...)' instead"
        )

    return asyncio.run(
        analyze_access_control_async(
            endpoints,
            response_cache=response_cache,
            limit=_coerce_limit(limit),
        )
    )
