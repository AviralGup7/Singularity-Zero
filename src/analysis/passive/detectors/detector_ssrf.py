import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    has_meaningful_parameters,
    has_remote_scheme,
    is_auth_flow_endpoint,
    is_dangerous_scheme,
    is_internal_host_value,
    is_low_value_endpoint,
    is_noise_url,
    looks_like_dns_callback,
    meaningful_query_pairs,
    normalized_confidence,
    parameter_weight,
    signal_weight,
)
from src.analysis.passive.patterns import SSRF_PARAM_NAMES

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.IGNORECASE)
_OCTAL_IP_RE = re.compile(r"\b0[0-7]+\.[0-7]+\.[0-7]+\.[0-7]+\b")
_HEX_IP_RE = re.compile(r"\b0x[0-9a-f]+\b", re.IGNORECASE)
_DEC_DNS_RE = re.compile(r"\b\d{8,}\.\w+\.\w{2,}\b")
_PROTOCOL_SMUGGLING_RE = re.compile(r"(?i)(?:gopher|dict|ldap|ldap[s]?|file|ftp|tftp|smb)://")
_CLOUD_METADATA_RE = re.compile(
    r"(?i)(?:169\.254\.169\.254|metadata\.google|metadata\.azure|100\.100\.100\.200|168\.63\.129\.16)"
)
_ENCODED_INTERNAL_RE = re.compile(
    r"(?i)(?:%31%32%37|%31%30%30|%31%39%32|127%2E|10%2E|192%2E|169%2E254)"
)
# DNS rebinding indicators: short-TTL domains, known rebinding services, numeric subdomains
_DNS_REBINDING_RE = re.compile(
    r"(?i)(?:\.rbndr\.us|\.nip\.io|\.sslip\.io|\.localtest\.me|\.vcap\.me|\.lvh\.me|\.burpcollaborator\.net|\.interact\.sh|\.requestbin\.net)"
)
_NUMERIC_SUBDOMAIN_RE = re.compile(r"(?i)^(?:\d{1,3}\.){3}\d{1,3}\.")


def _analyze_value_patterns(value: str, param_name: str) -> list[str]:
    """Analyze parameter value for SSRF-relevant patterns beyond basic scheme checks.

    Detects IP address formats, encoded internal hosts, protocol smuggling,
    cloud metadata endpoints, and DNS exfiltration patterns.

    Args:
        value: Parameter value to analyze.
        param_name: Name of the parameter (for signal labeling).

    Returns:
        List of detected signal strings.
    """
    signals = []
    lowered = value.lower().strip()

    if _IPV4_RE.search(value):
        signals.append(f"ipv4_address:{param_name}")
    if _IPV6_RE.search(value):
        signals.append(f"ipv6_address:{param_name}")
    if _OCTAL_IP_RE.search(value):
        signals.append(f"octal_ip_encoding:{param_name}")
    if _HEX_IP_RE.search(value):
        signals.append(f"hex_ip_encoding:{param_name}")
    if _CLOUD_METADATA_RE.search(value):
        signals.append(f"cloud_metadata_reference:{param_name}")
    if _ENCODED_INTERNAL_RE.search(value):
        signals.append(f"encoded_internal_host:{param_name}")
    if _PROTOCOL_SMUGGLING_RE.search(value):
        signals.append(f"protocol_smuggling_attempt:{param_name}")
    if _DEC_DNS_RE.search(value):
        signals.append(f"decimal_dns_exfil:{param_name}")

    parsed = urlparse(value)
    if parsed.port and parsed.port in {
        21,
        22,
        23,
        25,
        53,
        110,
        143,
        445,
        3306,
        3389,
        5432,
        6379,
        8080,
        8443,
        9200,
        27017,
    }:
        signals.append(f"sensitive_port_reference:{param_name}:{parsed.port}")

    if lowered.count("://") > 1:
        signals.append(f"nested_scheme:{param_name}")

    if lowered.startswith("data:") or lowered.startswith("blob:"):
        signals.append(f"data_blob_scheme:{param_name}")

    # DNS rebinding detection: known rebinding services and numeric subdomains
    if _DNS_REBINDING_RE.search(value):
        signals.append(f"dns_rebinding_service:{param_name}")
    if _NUMERIC_SUBDOMAIN_RE.search(value.split("://")[-1] if "://" in value else value):
        signals.append(f"numeric_subdomain_dns:{param_name}")

    return signals


def ssrf_candidate_finder(urls: set[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_patterns: set[str] = set()
    for raw_url in sorted(urls):
        if (
            is_low_value_endpoint(raw_url)
            or is_noise_url(raw_url)
            or not has_meaningful_parameters(raw_url)
        ):
            continue
        pattern_key = endpoint_signature(raw_url)
        if pattern_key in seen_patterns:
            continue
        seen_patterns.add(pattern_key)
        indicators: list[str] = []
        risky_params = []
        weighted_score = 0
        for normalized_key, decoded_value in meaningful_query_pairs(raw_url):
            lowered_value = decoded_value.lower() if decoded_value else ""

            # Always analyze value patterns for ALL parameters to catch encoded/sneaky patterns
            value_signals = (
                _analyze_value_patterns(decoded_value or "", normalized_key)
                if decoded_value
                else []
            )

            has_url_like_value = (
                "://" in lowered_value
                or lowered_value.startswith("http")
                or lowered_value.startswith("//")
                or lowered_value.startswith("data:")
                or lowered_value.startswith("blob:")
                or _IPV4_RE.search(decoded_value or "")
                or _PROTOCOL_SMUGGLING_RE.search(decoded_value or "")
            )

            # Expanded bypass list: common SSRF-adjacent param names that may carry
            # internal host references even without obvious URL-like values
            ssrf_adjacent_params = {
                "profile",
                "remote_auth_id",
                "return_to",
                "state",
                "server",
                "upstream",
                "backend",
                "origin",
                "fetch",
                "import_from",
                "source",
                "endpoint",
                "api_url",
                "webhook_url",
                "target_url",
                "redirect_uri",
                "next_url",
            }

            is_standard_ssrf_param = normalized_key in SSRF_PARAM_NAMES
            is_adjacent_param = normalized_key in ssrf_adjacent_params

            # Skip params that have no SSRF relevance
            if (
                not is_standard_ssrf_param
                and not is_adjacent_param
                and not has_url_like_value
                and not value_signals
            ):
                continue

            # Score URL-like values in non-standard params
            if has_url_like_value and not is_standard_ssrf_param:
                indicators.append(f"url_like_value_in_non_standard_param:{normalized_key}")
                weighted_score += 3

            # Value pattern signals are strong indicators regardless of param name
            if value_signals:
                indicators.extend(value_signals)
                weighted_score += len(value_signals) * 3

            # Adjacent params without URL-like values get lower score
            if not has_url_like_value and not value_signals and is_adjacent_param:
                indicators.append(f"ssrf_adjacent_param:{normalized_key}")
                weighted_score += 2

            if not decoded_value:
                continue
            risky_params.append(normalized_key)
            weighted_score += parameter_weight(normalized_key)
            if has_remote_scheme(decoded_value):
                indicators.append(f"remote_scheme:{normalized_key}")
            if is_dangerous_scheme(decoded_value):
                indicators.append(f"dangerous_scheme:{normalized_key}")
            if is_internal_host_value(decoded_value):
                indicators.append(f"internal_host_reference:{normalized_key}")
            if looks_like_dns_callback(decoded_value):
                indicators.append(f"dns_like_payload:{normalized_key}")
            if lowered_value.startswith("/"):
                indicators.append(f"path_like_value:{normalized_key}")
            if any(
                token in lowered_value for token in ("http", "://", ".com", ".net", ".org")
            ) and normalized_key in {"state", "profile"}:
                indicators.append(f"callback_like_oauth_value:{normalized_key}")
        if is_auth_flow_endpoint(raw_url) and any(
            param in {"return_to", "state", "profile", "remote_auth_id"} for param in risky_params
        ):
            indicators.append("oauth_redirect_sink")
            weighted_score += 3

        if risky_params and indicators:
            weighted_score += sum(signal_weight(signal) for signal in set(indicators))
            findings.append(
                {
                    "url": raw_url,
                    "endpoint_key": pattern_key,
                    "endpoint_type": classify_endpoint(raw_url),
                    "score": weighted_score,
                    "parameters": sorted(set(risky_params)),
                    "signals": sorted(set(indicators)),
                    "confidence": normalized_confidence(
                        base=0.46, score=weighted_score, signals=set(indicators), cap=0.94
                    ),
                }
            )

    findings.sort(key=lambda item: (-item["score"], -float(item.get("confidence", 0)), item["url"]))
    return findings[:120]
