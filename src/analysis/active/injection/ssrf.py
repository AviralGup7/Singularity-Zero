"""SSRF active probe."""

import json
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

SSRF_PATH_HINTS = {
    "webhook",
    "import",
    "fetch",
    "proxy",
    "callback",
    "preview",
    "download",
    "upload",
    "image",
    "url",
    "uri",
    "site",
    "load",
    "external",
    "remote",
}


def _analyze_metadata_response(body: str, provider: str) -> list[str]:
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
    return indicators


def ssrf_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test for SSRF via URL parameters, header injection, and POST bodies. (Fix Audit #9, #10)"""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    url_param_names = {
        "url",
        "uri",
        "path",
        "dest",
        "redirect",
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
        ("cloud_metadata_aws", "http://169.254.169.254/latest/meta-data/"),
        ("dns_rebind", "http://localtest.me"),
    ]

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "")).strip()
        if not url:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        # 1. Parameter-based SSRF
        if query_pairs:
            url_params = [
                (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in url_param_names
            ]
            for idx, param_name, _ in url_params:
                if len(url_probes) >= 2:
                    break
                for payload_name, payload_value in ssrf_payloads:
                    updated = list(query_pairs)
                    updated[idx] = (param_name, payload_value)
                    test_url = normalize_url(
                        urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                    )
                    response = response_cache.request(test_url, headers={"X-SSRF-Probe": "1"})
                    if response:
                        body = str(response.get("body_text", "") or "")[:8000]
                        indicators = _analyze_metadata_response(body, payload_name.split("_")[-1])
                        if indicators:
                            url_issues.extend(indicators)
                            url_probes.append(
                                {
                                    "parameter": param_name,
                                    "payload": payload_value,
                                    "type": "parameter",
                                    "issues": indicators,
                                }
                            )
                            break

        # 2. Header Injection SSRF (Fix Audit #9)
        if not url_probes:
            for inject_headers in HEADER_INJECTION_HEADERS:
                response = response_cache.request(
                    url, headers={**inject_headers, "X-SSRF-Probe": "1"}
                )
                if response:
                    body = str(response.get("body_text", "") or "")[:8000]
                    indicators = _analyze_metadata_response(body, "generic")
                    if indicators:
                        url_issues.extend(indicators)
                        url_probes.append(
                            {
                                "headers": inject_headers,
                                "type": "header_injection",
                                "issues": indicators,
                            }
                        )
                        break

        # 3. POST Body SSRF for suggestive paths (Fix Audit #10)
        path_lower = parsed.path.lower()
        if not url_probes and any(hint in path_lower for hint in SSRF_PATH_HINTS):
            for payload_name, payload_value in ssrf_payloads:
                test_body = json.dumps(
                    {"url": payload_value, "uri": payload_value, "path": payload_value}
                )
                response = response_cache.request(
                    url,
                    method="POST",
                    body=test_body,
                    headers={"Content-Type": "application/json", "X-SSRF-Probe": "1"},
                )
                if response:
                    body = str(response.get("body_text", "") or "")[:8000]
                    indicators = _analyze_metadata_response(body, payload_name.split("_")[-1])
                    if indicators:
                        url_issues.extend(indicators)
                        url_probes.append(
                            {"body": test_body, "type": "post_body", "issues": indicators}
                        )
                        break

        if url_probes:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": sorted(list(set(url_issues))),
                    "probes": url_probes,
                    "confidence": probe_confidence(url_issues),
                    "severity": probe_severity(url_issues),
                }
            )

    return findings[:limit]
