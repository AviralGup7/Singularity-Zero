"""JSON mutation attack probes."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import (
    AUTH_SKIP_PARAMS,
    REDIRECT_PARAM_NAMES,
    classify_endpoint,
    decode_candidate_value,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
)
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from .diff import _variant_diff_summary


def _json_mutation_variants(name: str, value: str) -> list[tuple[str, str]]:
    lowered = name.lower()
    if lowered in {
        "fields",
        "include",
        "expand",
        "filter",
        "where",
        "query",
        "payload",
        "data",
        "input",
    }:
        return [
            ("json_object", '{"probe":true}'),
            ("json_array", '["probe","alt"]'),
            ("json_boolean", "true"),
            ("json_null", "null"),
            ("json_nested_object", '{"a":{"b":{"c":"deep"}}}'),
            ("sqli_string", '{"probe":"\' OR 1=1 --"}'),
            ("type_confusion_number", "9999999999999999"),
        ]
    return [
        ("json_object", '{"value":"probe"}'),
        ("json_array", '["probe"]'),
        ("json_null", "null"),
        ("json_boolean", "false"),
        ("type_confusion_string", '"123"'),
        ("integer_overflow", "9999999999999999"),
    ]


def json_mutation_attacks(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 16
) -> list[dict[str, Any]]:
    """Test JSON mutation attacks on query parameters."""
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not url or is_noise_url(url):
            continue
        baseline = response_cache.get(url)
        if not baseline:
            continue
        content_type = str(baseline.get("content_type", "")).lower()
        if classify_endpoint(url) != "API" and "json" not in content_type:
            continue
        parsed = urlparse(url)
        raw_query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not raw_query_pairs:
            continue
        url_endpoint_key = endpoint_signature(url)
        url_endpoint_base_key = endpoint_base_key(url)
        for key, value in raw_query_pairs:
            parameter = key.strip().lower()
            if not parameter or parameter in REDIRECT_PARAM_NAMES or parameter in AUTH_SKIP_PARAMS:
                continue
            observations = []
            for variant_name, variant_value in _json_mutation_variants(
                parameter, decode_candidate_value(value)
            ):
                mutated_pairs = [
                    (pk, pv) if pk != key else (pk, variant_value) for pk, pv in raw_query_pairs
                ]
                mutated_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(mutated_pairs, doseq=True)))
                )
                mutated = response_cache.request(
                    mutated_url,
                    headers={"Cache-Control": "no-cache", "X-JSON-Mutation": variant_name},
                )
                if not mutated:
                    continue
                diff = _variant_diff_summary(baseline, mutated)
                if not (
                    diff["changed"] or diff["status_changed"] or diff["body_similarity"] < 0.97
                ):
                    continue
                observations.append(
                    {
                        "variant": variant_name,
                        "mutated_value": variant_value,
                        "mutated_url": mutated_url,
                        **diff,
                    }
                )
            if observations:
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": url_endpoint_key,
                        "endpoint_base_key": url_endpoint_base_key,
                        "parameter": parameter,
                        "content_type": baseline.get("content_type", ""),
                        "observations": observations[:3],
                        "signals": [
                            "json_mutation_probe",
                            "status_divergence"
                            if any(item["status_changed"] for item in observations)
                            else "content_divergence",
                        ],
                    }
                )
                continue
    findings.sort(key=lambda item: (-len(item["observations"]), item["url"]))
    return findings[:limit]
