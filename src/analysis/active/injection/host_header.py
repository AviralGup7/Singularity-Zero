"""Host header injection probe."""

from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache

from ._confidence import probe_confidence, probe_severity


def host_header_injection_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Send requests with manipulated Host headers.

    Sends requests with Host, X-Forwarded-Host, X-Host, X-HTTP-Host-Override
    headers pointing to attacker-controlled domains. Checks responses for
    reflected host headers in Location, Content-Location, links, and
    password reset URLs.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of host header injection findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    attacker_host = "evil-attacker-test.com"

    host_header_variants = [
        ("host", {"Host": attacker_host}),
        ("x_forwarded_host", {"X-Forwarded-Host": attacker_host}),
        ("x_host", {"X-Host": attacker_host}),
        ("x_http_host_override", {"X-HTTP-Host-Override": attacker_host}),
        ("forwarded", {"Forwarded": f'host="{attacker_host}"'}),
        ("x_forwarded_for_host", {"X-Forwarded-For": attacker_host}),
    ]

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for header_name, custom_headers in host_header_variants:
            if len(url_probes) >= 2:
                break

            response = response_cache.request(
                url,
                headers={
                    "Cache-Control": "no-cache",
                    "X-HostHeader-Probe": "1",
                    **custom_headers,
                },
            )
            if not response:
                continue

            body = str(response.get("body_text", "") or "")[:8000]
            status = int(response.get("status_code") or 0)
            headers = {
                str(key).lower(): str(value)
                for key, value in (response.get("headers") or {}).items()
            }

            issues_for_hit: list[str] = []

            location = headers.get("location", "")
            content_location = headers.get("content-location", "")

            if attacker_host in location.lower():
                issues_for_hit.append("host_header_reflection_location")
            elif attacker_host in content_location.lower():
                issues_for_hit.append("host_header_reflection_location")
            elif attacker_host in body.lower():
                if "password" in body.lower() or "reset" in body.lower() or "token" in body.lower():
                    issues_for_hit.append("host_header_password_reset_poison")
                else:
                    issues_for_hit.append("host_header_reflection_body")

            if issues_for_hit:
                url_issues.extend(issues_for_hit)
                url_probes.append(
                    {
                        "header": header_name,
                        "attacker_host": attacker_host,
                        "status_code": status,
                        "location_reflection": attacker_host in location.lower(),
                        "body_reflection": attacker_host in body.lower(),
                        "issues": issues_for_hit,
                    }
                )

        if url_probes:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": url_issues,
                    "probes": url_probes,
                    "confidence": probe_confidence(url_issues),
                    "severity": probe_severity(url_issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]
