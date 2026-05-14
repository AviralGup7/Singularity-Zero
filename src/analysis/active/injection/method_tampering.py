"""HTTP Method Override / Method Tampering analysis module.

Tests discovered endpoints for HTTP method tampering vulnerabilities:
- Accepting alternate methods (PUT, DELETE, PATCH, TRACE)
- HTTP method override headers (X-HTTP-Method-Override, X-Method-Override)
- Web verb tampering (IIS-specific)

Returns findings for endpoints that accept unexpected methods or are
vulnerable to method override headers.
"""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

ALTERNATE_METHODS = ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]

OVERRIDE_HEADERS = {
    "X-HTTP-Method": "PUT",
    "X-HTTP-Method-Override": "PUT",
    "X-Method-Override": "PUT",
}

METHOD_OVERRIDE_STATUS_CHANGES = frozenset({200, 201, 204, 405, 500, 501})


async def test_method_tampering(
    urls: list[str],
    timeout: float = 10.0,
    max_urls: int = 200,
    verify_tls: bool = False,
) -> list[dict[str, Any]]:
    """Test endpoints for HTTP method tampering vulnerabilities.

    Args:
        urls: List of URLs to test.
        timeout: Per-request timeout in seconds.
        max_urls: Maximum number of URLs to test (performance cap).
        verify_tls: Whether to verify TLS certificates.

    Returns:
        List of findings dicts with keys: url, type, method/header,
        baseline_status, response_status, details.
    """
    if not urls:
        return []

    findings: list[dict[str, Any]] = _deduplicate_urls(urls)
    findings.clear()

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        verify=verify_tls,
        headers={"User-Agent": "cyber-pipeline/1.0"},
    ) as client:
        tested = 0
        for url in urls[:max_urls]:
            findings.extend(await _test_single_url(client, url))
            tested += 1

    logger.info(
        "Method tampering: tested %d URLs, found %d findings",
        tested,
        len(findings),
    )
    return findings


async def _test_single_url(
    client: httpx.AsyncClient,
    url: str,
) -> list[dict[str, Any]]:
    """Test a single URL for method tampering."""
    findings: list[dict[str, Any]] = []

    try:
        baseline = await client.get(url)
    except httpx.RequestError:
        return findings

    # Test 1: Alternate HTTP methods
    for method in ALTERNATE_METHODS:
        try:
            resp = await client.request(method, url)
            # 405 = Method Not Allowed (expected for unsupported methods)
            # 501 = Not Implemented (also expected)
            # If we get 2xx-4xx (except 405/501), the method was accepted
            if resp.status_code not in (405, 501, 404, 403, 401) and resp.status_code >= 200:
                findings.append(
                    {
                        "url": url,
                        "type": "unexpected_method_accepted",
                        "method": method,
                        "method_baseline": "GET",
                        "baseline_status": baseline.status_code,
                        "response_status": resp.status_code,
                        "response_length": len(resp.text),
                        "details": (
                            f"Method {method} returned status {resp.status_code} "
                            f"(baseline GET returned {baseline.status_code})"
                        ),
                    }
                )
        except httpx.RequestError:
            continue

    # Test 2: Method override headers
    for header_name, header_value in OVERRIDE_HEADERS.items():
        try:
            resp = await client.get(
                url,
                headers={header_name: header_value},
            )
            # If the response differs from the baseline, the server
            # may be honouring the override header
            if resp.status_code != baseline.status_code and (
                resp.status_code < 400 or resp.status_code in METHOD_OVERRIDE_STATUS_CHANGES
            ):
                findings.append(
                    {
                        "url": url,
                        "type": "method_override_accepted",
                        "header": f"{header_name}: {header_value}",
                        "baseline_status": baseline.status_code,
                        "response_status": resp.status_code,
                        "details": (
                            f"Header {header_name} changed response from "
                            f"{baseline.status_code} to {resp.status_code}"
                        ),
                    }
                )
        except httpx.RequestError:
            continue

    return findings


def _deduplicate_urls(urls: list[str]) -> list[dict]:
    """Validate and return a working findings list reference."""
    return []
