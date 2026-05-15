"""Token manipulation attacks via JWT stripping."""

import logging
from typing import Any

from src.analysis._core.http_request import _safe_request
from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    probe_confidence,
    probe_severity,
)
from src.analysis.passive.runtime import ResponseCache

from ._helpers import (
    AUTH_HEADERS,
    _extract_jwt_from_headers,
)

logger = logging.getLogger(__name__)


def probe_token_manipulation(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Remove JWT tokens from Authorization headers and check if endpoints still respond.

    For each URL that has an existing JWT token in headers, re-request the
    endpoint with the Authorization header stripped entirely. If the endpoint
    returns the same or similar data without authentication, it indicates
    an auth bypass.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of JWT stripping findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        original_resp = response_cache.get(url)
        if not original_resp:
            original_resp = _safe_request(url, timeout=8)
        if not original_resp or original_resp.get("status") in (404, 410, 503):
            continue

        original_status = original_resp.get("status", 0)
        original_headers = original_resp.get("headers", {})
        original_body = str(original_resp.get("body") or original_resp.get("body_text") or "")

        jwt_token = _extract_jwt_from_headers(original_headers)
        if not jwt_token:
            continue

        stripped_headers = {
            k: v
            for k, v in original_headers.items()
            if k.lower() not in {h.lower() for h in AUTH_HEADERS}
        }

        logger.debug("Probing JWT stripping on %s", url)
        response = _safe_request(url, headers=stripped_headers, timeout=10)
        if not response:
            continue

        status = response.get("status", 0)
        body = str(response.get("body") or "")

        if status == 200 and original_status in (401, 403):
            issues = ["jwt_stripping_bypass"]
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": issues,
                    "probe_type": "jwt_stripping",
                    "original_status": original_status,
                    "stripped_status": status,
                    "evidence": {
                        "original_status": original_status,
                        "stripped_status": status,
                        "body_length_delta": len(body) - len(original_body[:8000]),
                    },
                    "confidence": probe_confidence(issues),
                    "severity": probe_severity(issues),
                }
            )
        elif status == 200 and original_status in (200, 301, 302, 0):
            body_similarity = 1.0
            if original_body and body:
                orig_len = len(original_body[:8000])
                stripped_len = len(body[:8000])
                if orig_len > 0:
                    body_similarity = min(orig_len, stripped_len) / max(orig_len, stripped_len)
            if body_similarity > 0.7:
                issues = ["jwt_stripping_partial_access"]
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": endpoint_base_key(url),
                        "endpoint_type": classify_endpoint(url),
                        "issues": issues,
                        "probe_type": "jwt_stripping",
                        "original_status": original_status,
                        "stripped_status": status,
                        "body_similarity": round(body_similarity, 2),
                        "evidence": {
                            "original_status": original_status,
                            "stripped_status": status,
                            "body_similarity": round(body_similarity, 2),
                        },
                        "confidence": probe_confidence(issues),
                        "severity": probe_severity(issues),
                    }
                )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]


probe_jwt_stripping = probe_token_manipulation
