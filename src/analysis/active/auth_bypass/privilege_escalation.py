"""Privilege escalation via auth bypass parameter injection."""

import json
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
    AUTH_BYPASS_PARAMS,
)

logger = logging.getLogger(__name__)


def probe_privilege_escalation(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Test common bypass patterns (admin=true, role=admin, bypass=1, etc.).

    Injects auth bypass parameters into query strings and POST bodies to
    detect endpoints that trust client-supplied role/privilege values.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of auth bypass pattern findings.
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
        str(original_resp.get("body") or original_resp.get("body_text") or "")

        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

        parsed = urlparse(url)
        existing_params = dict(parse_qsl(parsed.query, keep_blank_values=True))

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for param_name, bypass_values in AUTH_BYPASS_PARAMS.items():
            for bypass_val in bypass_values:
                test_params = dict(existing_params)
                test_params[param_name] = bypass_val
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

                logger.debug("Probing auth bypass param %s=%s on %s", param_name, bypass_val, url)
                response = _safe_request(test_url, headers=original_headers, timeout=10)
                if not response:
                    continue

                status = response.get("status", 0)
                body = str(response.get("body") or "")

                if status == 200 and original_status in (401, 403):
                    issue_key = f"param_bypass_{param_name}_{bypass_val}"
                    url_issues.append(issue_key)
                    url_probes.append(
                        {
                            "type": "query_param",
                            "parameter": param_name,
                            "value": bypass_val,
                            "original_status": original_status,
                            "bypass_status": status,
                        }
                    )
                    break
                elif status == 200 and original_status in (200, 0):
                    body_lower = body.lower()
                    admin_indicators = ["admin", "superuser", "root", "privilege", "elevated"]
                    if any(ind in body_lower for ind in admin_indicators):
                        if param_name in ("admin", "role", "is_admin"):
                            issue_key = f"param_bypass_{param_name}_{bypass_val}"
                            url_issues.append(issue_key)
                            url_probes.append(
                                {
                                    "type": "query_param",
                                    "parameter": param_name,
                                    "value": bypass_val,
                                    "status": status,
                                    "body_indicator": True,
                                }
                            )
                            break

            if url_issues:
                break

        if not url_issues:
            for param_name, bypass_values in AUTH_BYPASS_PARAMS.items():
                for bypass_val in bypass_values[:1]:
                    json_body = json.dumps({param_name: bypass_val}).encode()
                    post_headers = dict(original_headers)
                    post_headers["Content-Type"] = "application/json"

                    logger.debug(
                        "Probing auth bypass body %s=%s on %s", param_name, bypass_val, url
                    )
                    response = _safe_request(
                        url, headers=post_headers, body=json_body, method="POST", timeout=10
                    )
                    if not response:
                        continue

                    status = response.get("status", 0)
                    body = str(response.get("body") or "")

                    if status == 200 and original_status in (401, 403):
                        url_issues.append("param_body_bypass")
                        url_probes.append(
                            {
                                "type": "body_param",
                                "parameter": param_name,
                                "value": bypass_val,
                                "original_status": original_status,
                                "bypass_status": status,
                            }
                        )
                        break
                    elif status == 200 and original_status in (200, 0):
                        body_lower = body.lower()
                        if param_name in ("admin", "role", "is_admin"):
                            admin_indicators = ["admin", "superuser", "root"]
                            if any(ind in body_lower for ind in admin_indicators):
                                url_issues.append("param_body_bypass")
                                url_probes.append(
                                    {
                                        "type": "body_param",
                                        "parameter": param_name,
                                        "value": bypass_val,
                                        "status": status,
                                        "body_indicator": True,
                                    }
                                )
                                break

                if url_issues:
                    break

        if url_probes:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": url_issues,
                    "probe_type": "auth_bypass_patterns",
                    "probes": url_probes,
                    "confidence": probe_confidence(url_issues),
                    "severity": probe_severity(url_issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]


probe_auth_bypass_patterns = probe_privilege_escalation
