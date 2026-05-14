"""Parameter pollution exploitation probes."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import (
    REDIRECT_PARAM_NAMES,
    decode_candidate_value,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
)
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from .diff import _variant_diff_summary

AUTH_SKIP_PARAMS = {
    "token",
    "session",
    "jwt",
    "auth",
    "api_key",
    "access_token",
    "refresh_token",
    "client_id",
    "client_secret",
    "authorization",
    "bearer",
    "cookie",
    "sid",
    "phpsessid",
}


def _parameter_pollution_variant(name: str, value: str) -> str:
    if value.isdigit():
        return str(max(int(value) + 1, 2))
    if name in {"role", "roles", "scope", "permission", "permissions"}:
        return "admin"
    if name in REDIRECT_PARAM_NAMES:
        return "/admin"
    if name in {"include", "expand", "fields", "view", "filter"}:
        return "all"
    return "__dup__"


def _all_parameter_pollution_variants(name: str, value: str) -> list[str]:
    variants: list[str] = []
    primary = _parameter_pollution_variant(name, value)
    if primary:
        variants.append(primary)
    if value.isdigit():
        numeric_val = int(value)
        if numeric_val > 0:
            variants.append(str(numeric_val - 1))
        variants.extend(["0", "999999999", "-1"])
    elif name in {"role", "roles", "scope", "permission", "permissions"}:
        variants.extend(["superadmin", "root", "owner", "administrator"])
    elif name in REDIRECT_PARAM_NAMES:
        variants.extend(
            ["//evil.com", "https://evil.com", "/../../etc/passwd", "javascript:alert(1)"]
        )
    elif name in {"include", "expand", "fields", "view", "filter"}:
        variants.extend(["*", "all,secret,hidden", "__proto__", "constructor"])
    else:
        variants.extend(["__proto__", "constructor", value + "__dup__"])
    seen: set[str] = set()
    unique: list[str] = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique[:6]


def parameter_pollution_exploitation(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 16
) -> list[dict[str, Any]]:
    """Test for HTTP parameter pollution vulnerabilities."""
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not url or is_noise_url(url):
            continue
        parsed = urlparse(url)
        raw_query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not raw_query_pairs:
            continue
        baseline = response_cache.get(url)
        if not baseline:
            continue
        url_endpoint_key = endpoint_signature(url)
        url_endpoint_base_key = endpoint_base_key(url)
        for key, value in raw_query_pairs:
            parameter = key.strip().lower()
            if not parameter or parameter in AUTH_SKIP_PARAMS:
                continue
            pollution_values = _all_parameter_pollution_variants(
                parameter, decode_candidate_value(value)
            )
            for pollution_value in pollution_values:
                polluted_url = normalize_url(
                    urlunparse(
                        parsed._replace(
                            query=urlencode([*raw_query_pairs, (key, pollution_value)], doseq=True)
                        )
                    )
                )
                polluted = response_cache.request(
                    polluted_url,
                    headers={"Cache-Control": "no-cache", "X-Parameter-Pollution": "1"},
                )
                if not polluted:
                    continue
                diff = _variant_diff_summary(baseline, polluted)
                if not (
                    diff["changed"] or diff["status_changed"] or diff["body_similarity"] < 0.97
                ):
                    continue
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": url_endpoint_key,
                        "endpoint_base_key": url_endpoint_base_key,
                        "parameter": parameter,
                        "original_value": decode_candidate_value(value),
                        "pollution_value": pollution_value,
                        "mutated_url": polluted_url,
                        "strategy": "duplicate_parameter_append",
                        "signals": [
                            "duplicate_parameter_append",
                            "status_divergence" if diff["status_changed"] else "content_divergence",
                        ],
                        **diff,
                    }
                )
        for key, value in raw_query_pairs:
            parameter = key.strip().lower()
            if not parameter or parameter in AUTH_SKIP_PARAMS:
                continue
            array_variants = [
                (f"{key}[]", decode_candidate_value(value)),
                (f"{key}[0]", decode_candidate_value(value)),
            ]
            for array_key, array_val in array_variants:
                pollution_val = _parameter_pollution_variant(parameter, array_val)
                base_pairs = [(k, v) for k, v in raw_query_pairs if k.lower() != parameter]
                polluted_pairs = base_pairs + [(array_key, array_val), (array_key, pollution_val)]
                polluted_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(polluted_pairs, doseq=True)))
                )
                polluted = response_cache.request(
                    polluted_url, headers={"Cache-Control": "no-cache", "X-Array-Pollution": "1"}
                )
                if not polluted:
                    continue
                diff = _variant_diff_summary(baseline, polluted)
                if not (
                    diff["changed"] or diff["status_changed"] or diff["body_similarity"] < 0.95
                ):
                    continue
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": url_endpoint_key,
                        "endpoint_base_key": url_endpoint_base_key,
                        "parameter": parameter,
                        "pollution_style": "array_indexed",
                        "array_key": array_key,
                        "pollution_value": pollution_val,
                        "mutated_url": polluted_url,
                        "strategy": "array_parameter_pollution",
                        "signals": [
                            "array_parameter_pollution",
                            "status_divergence" if diff["status_changed"] else "content_divergence",
                        ],
                        **diff,
                    }
                )
    findings.sort(
        key=lambda item: (not item["status_changed"], not item["content_changed"], item["url"])
    )
    return findings[:limit]
