"""Token leak detector for finding exposed tokens in URLs and responses.

Scans URLs for token-like parameters (JWT, session tokens, API keys) and
response bodies for token exposure in headers, body content, and referer
risks. Groups findings by endpoint and calculates replay likelihood.
"""

from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    has_meaningful_parameters,
    is_low_value_endpoint,
    is_noise_url,
    is_third_party_auth_host,
    meaningful_query_pairs,
    replay_likelihood,
    same_host_family,
    token_shape,
)
from src.analysis.passive.patterns import (
    EXTERNAL_REFERENCE_RE,
    JWT_RE,
    SENSITIVE_PATTERNS,
    TOKEN_PARAM_NAMES,
)
from src.analysis.passive.runtime import redact_value


def _context_severity_score(
    location: str,
    token_shapes: set[str],
    indicators: set[str],
    status_code: int | None,
    repeat_count: int,
) -> float:
    """Calculate a context-aware severity score for token exposure.

    Considers token location, shape, type, HTTP status, and repetition
    to produce a more nuanced severity assessment.

    Args:
        location: Where the token was found (query_parameter, response_body, referer_risk).
        token_shapes: Set of detected token shapes (jwt, api_key, etc.).
        indicators: Set of token indicator names.
        status_code: HTTP status code of the response.
        repeat_count: Number of times the token pattern was found.

    Returns:
        Severity score from 0.0 to 1.0.
    """
    base_score = 0.5

    location_scores = {
        "response_body": 0.25,
        "referer_risk": 0.20,
        "header": 0.15,
        "query_parameter": 0.10,
    }
    base_score += location_scores.get(location, 0.05)

    if "jwt" in token_shapes or "bearer_token" in token_shapes:
        base_score += 0.12
    if (
        "private_key_block" in indicators
        or "aws_access_key" in indicators
        or "stripe_secret" in indicators
    ):
        base_score += 0.15
    if any("api_key" in ind or "secret" in ind for ind in indicators):
        base_score += 0.08

    if status_code and status_code == 200:
        base_score += 0.05
    if repeat_count >= 3:
        base_score += 0.08
    elif repeat_count >= 2:
        base_score += 0.04

    return round(min(base_score, 1.0), 2)


def token_leak_detector(urls: set[str], responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect token exposure in URLs and HTTP responses.

    Args:
        urls: Set of URLs to scan for token parameters.
        responses: List of HTTP response dicts to scan for token leaks.

    Returns:
        List of token leak findings grouped by location and endpoint.
    """
    findings: list[dict[str, Any]] = []
    query_groups: dict[str, dict[str, Any]] = {}
    response_groups: dict[str, dict[str, Any]] = {}

    for raw_url in sorted(urls):
        if (
            is_low_value_endpoint(raw_url)
            or is_noise_url(raw_url)
            or not has_meaningful_parameters(raw_url)
        ):
            continue
        endpoint_key = endpoint_signature(raw_url)
        group = query_groups.setdefault(
            endpoint_key,
            {
                "url": raw_url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base_key(raw_url),
                "endpoint_type": classify_endpoint(raw_url),
                "location": "query_parameter",
                "indicators": set(),
                "token_shapes": set(),
                "sample_values": [],
                "urls": set(),
            },
        )
        group["urls"].add(raw_url)
        for normalized_key, decoded_value in meaningful_query_pairs(raw_url):
            if normalized_key not in TOKEN_PARAM_NAMES or not decoded_value:
                continue
            group["indicators"].add(normalized_key)
            group["token_shapes"].add(token_shape(decoded_value))
            if len(group["sample_values"]) < 3:
                group["sample_values"].append(redact_value(decoded_value))

    for group in query_groups.values():
        if not group["indicators"]:
            continue
        context_severity = _context_severity_score(
            location="query_parameter",
            token_shapes=group["token_shapes"],
            indicators=group["indicators"],
            status_code=None,
            repeat_count=len(group["urls"]),
        )
        findings.append(
            {
                "url": group["url"],
                "endpoint_key": group["endpoint_key"],
                "endpoint_base_key": group["endpoint_base_key"],
                "endpoint_type": group["endpoint_type"],
                "location": "query_parameter",
                "indicator": ",".join(sorted(group["indicators"])),
                "indicators": sorted(group["indicators"]),
                "token_shapes": sorted(group["token_shapes"]),
                "redacted_value": group["sample_values"][0] if group["sample_values"] else "",
                "sample_values": group["sample_values"],
                "leak_count": len(group["indicators"]) + max(0, len(group["urls"]) - 1),
                "urls": sorted(group["urls"])[:12],
                "context_severity": context_severity,
                "signals": sorted(
                    {f"token_shape:{shape}" for shape in group["token_shapes"]}
                    | ({"reused_across_urls"} if len(group["urls"]) > 1 else set())
                ),
            }
        )

    for response in responses:
        if is_noise_url(str(response.get("url", ""))):
            continue
        body = response.get("body_text") or ""
        if not body:
            continue
        response_host = urlparse(response["url"]).netloc.lower()
        token_params = {
            key
            for key, value in meaningful_query_pairs(response["url"])
            if key in TOKEN_PARAM_NAMES and value
        }
        if token_params:
            external_hosts = sorted(
                {
                    urlparse(match.group(0)).netloc.lower()
                    for match in EXTERNAL_REFERENCE_RE.finditer(body)
                    if urlparse(match.group(0)).netloc.lower()
                    and not same_host_family(urlparse(match.group(0)).netloc.lower(), response_host)
                    and not is_third_party_auth_host(
                        urlparse(match.group(0)).netloc.lower(), response_host
                    )
                }
            )
            if external_hosts:
                findings.append(
                    {
                        "url": response["url"],
                        "endpoint_key": endpoint_signature(response["url"]),
                        "endpoint_base_key": endpoint_base_key(response["url"]),
                        "endpoint_type": classify_endpoint(response["url"]),
                        "status_code": response.get("status_code"),
                        "location": "referer_risk",
                        "indicator": ",".join(sorted(token_params)),
                        "indicators": sorted(token_params),
                        "external_hosts": external_hosts[:8],
                        "leak_count": len(token_params),
                        "signals": ["external_reference_with_token"],
                    }
                )
        # Scan response body for ALL sensitive token patterns, not just JWT/bearer
        # This catches API keys, AWS keys, private keys, and other credential leaks
        token_patterns = [("jwt", JWT_RE)]
        for pattern_name, pattern_regex in SENSITIVE_PATTERNS:
            if pattern_regex is not None:
                token_patterns.append((pattern_name, pattern_regex))
        for label, pattern in token_patterns:
            for match in pattern.finditer(body):
                group_key = endpoint_signature(response["url"])
                group = response_groups.setdefault(
                    group_key,
                    {
                        "url": response["url"],
                        "endpoint_key": endpoint_signature(response["url"]),
                        "endpoint_base_key": endpoint_base_key(response["url"]),
                        "endpoint_type": classify_endpoint(response["url"]),
                        "status_code": response.get("status_code"),
                        "location": "response_body",
                        "indicators": set(),
                        "token_shapes": set(),
                        "sample_values": [],
                        "repeat_count": 0,
                    },
                )
                group["indicators"].add(label)
                group["token_shapes"].add(token_shape(match.group(0)))
                group["repeat_count"] += 1
                if len(group["sample_values"]) < 3:
                    group["sample_values"].append(redact_value(match.group(0)))

    for group in response_groups.values():
        signals = {f"token_shape:{shape}" for shape in group["token_shapes"]}
        if group["repeat_count"] > 1:
            signals.add("repeated_token_reuse")
        context_severity = _context_severity_score(
            location="response_body",
            token_shapes=group["token_shapes"],
            indicators=group["indicators"],
            status_code=group.get("status_code"),
            repeat_count=group["repeat_count"],
        )
        findings.append(
            {
                "url": group["url"],
                "endpoint_key": group["endpoint_key"],
                "endpoint_base_key": group["endpoint_base_key"],
                "endpoint_type": group["endpoint_type"],
                "status_code": group["status_code"],
                "location": group["location"],
                "indicator": ",".join(sorted(group["indicators"])),
                "indicators": sorted(group["indicators"]),
                "token_shapes": sorted(group["token_shapes"]),
                "redacted_value": group["sample_values"][0] if group["sample_values"] else "",
                "sample_values": group["sample_values"],
                "leak_count": max(
                    group["repeat_count"], len(group["sample_values"]), len(group["indicators"])
                ),
                "repeat_count": group["repeat_count"],
                "context_severity": context_severity,
                "replay_likelihood": replay_likelihood(
                    "response_body", sorted(group["token_shapes"]), group["repeat_count"]
                ),
                "signals": sorted(signals),
            }
        )

    # Sort by severity: response_body (most critical) first, then referer_risk, then query_parameter
    location_priority = {"response_body": 0, "referer_risk": 1, "query_parameter": 2, "header": 3}
    findings.sort(
        key=lambda item: (
            location_priority.get(item.get("location", ""), 99),
            -item.get("context_severity", 0),
            -item.get("leak_count", 0),
            item.get("url", ""),
        )
    )
    return findings[:120]
