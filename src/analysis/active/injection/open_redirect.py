"""Open redirect active probe."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from ._confidence import probe_confidence, probe_severity


def open_redirect_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test redirect/callback parameters with external URLs.

    Sends payloads like //evil.com, https://evil.com to redirect-like
    parameters. Checks Location headers and response bodies for redirects
    to external domains.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of open redirect findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    redirect_param_names = {
        "redirect",
        "url",
        "next",
        "target",
        "dest",
        "destination",
        "return",
        "returnto",
        "return_url",
        "redirect_url",
        "redirect_uri",
        "callback",
        "continue",
        "continueto",
        "goto",
        "back",
        "referer",
        "ref",
        "out",
        "forward",
        "go",
        "link",
        "uri",
        "path",
        "to",
        "navigate",
        "redir",
        "r",
        "u",
        "returnurl",
        "redirectto",
    }

    redirect_payloads = [
        ("protocol_relative", "//evil.com"),
        ("https_external", "https://evil.com"),
        ("google_redirect", "//google.com"),
        ("encoded_slash_slash", "%2f%2fevil.com"),
        ("double_url_encoded", "%252f%252fevil.com"),
        ("backslash_bypass", "//evil.com\\@target.com"),
        ("dot_prefix", "/././evil.com"),
        ("tab_newline_bypass", "https://evil.com\ttarget.com"),
        ("at_sign_bypass", "//evil.com@good.com"),
        ("semicolon_bypass", "//good.com;evil.com"),
    ]

    external_domains = {"evil.com", "google.com"}

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        redirect_params = [
            (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in redirect_param_names
        ]
        if not redirect_params:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for idx, param_name, _param_value in redirect_params:
            if len(url_probes) >= 2:
                break
            for payload_name, payload_value in redirect_payloads:
                updated = list(query_pairs)
                updated[idx] = (param_name, payload_value)
                test_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                )

                response = response_cache.request(
                    test_url,
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Redirect-Probe": "1",
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
                original_host = parsed.hostname or ""

                if any(domain in location.lower() for domain in external_domains):
                    issues_for_hit.append("open_redirect_location_header")
                elif 300 <= status < 400 and location:
                    loc_parsed = urlparse(location)
                    loc_host = loc_parsed.hostname or ""
                    if loc_host and loc_host.lower() != original_host.lower():
                        issues_for_hit.append("open_redirect_status_3xx")
                elif any(domain in body.lower() for domain in external_domains):
                    issues_for_hit.append("open_redirect_body_reflection")

                if issues_for_hit:
                    url_issues.extend(issues_for_hit)
                    url_probes.append(
                        {
                            "parameter": param_name,
                            "payload": payload_value,
                            "payload_type": payload_name,
                            "status_code": status,
                            "location": location,
                            "issues": issues_for_hit,
                        }
                    )
                    break

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
