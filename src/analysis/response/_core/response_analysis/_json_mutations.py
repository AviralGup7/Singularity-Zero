"""JSON mutation attacks on query and POST body parameters."""

import json
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

from ._diff_utils import variant_diff_summary


def json_mutation_attacks(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 16
) -> list[dict[str, Any]]:
    """Test query parameters with JSON-shaped mutations."""
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
        for key, value in raw_query_pairs:
            parameter = key.strip().lower()
            if not parameter or parameter in REDIRECT_PARAM_NAMES or parameter in AUTH_SKIP_PARAMS:
                continue
            observations = []
            for variant_name, variant_value in _json_mutation_variants(
                parameter, decode_candidate_value(value)
            ):
                mutated_pairs = [
                    (pair_key, pair_value) if pair_key != key else (pair_key, variant_value)
                    for pair_key, pair_value in raw_query_pairs
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
                diff = variant_diff_summary(baseline, mutated)
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
                        "endpoint_key": endpoint_signature(url),
                        "endpoint_base_key": endpoint_base_key(url),
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


def post_body_mutation_attacks(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 12
) -> list[dict[str, Any]]:
    """Test POST body parameters for type confusion and boundary value vulnerabilities."""
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
        body_text = baseline.get("body_text") or ""
        try:
            original_body = json.loads(body_text)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(original_body, dict):
            continue
        mutations = [
            (
                "null_injection",
                {**original_body, **{k: None for k in list(original_body.keys())[:2]}},
            ),
            (
                "type_confusion_bool",
                {**original_body, **{k: True for k in list(original_body.keys())[:1]}},
            ),
            (
                "type_confusion_string",
                {**original_body, **{k: "true" for k in list(original_body.keys())[:1]}},
            ),
            (
                "prototype_pollution",
                {
                    **original_body,
                    "__proto__": {"isAdmin": True},
                    "constructor": {"prototype": {"isAdmin": True}},
                },
            ),
            (
                "array_injection",
                {**original_body, **{k: [] for k in list(original_body.keys())[:1]}},
            ),
            (
                "object_injection",
                {
                    **original_body,
                    **{k: {"injected": True} for k in list(original_body.keys())[:1]},
                },
            ),
        ]
        numeric_keys = [
            k for k in original_body.keys() if isinstance(original_body.get(k), (int, float))
        ]
        if numeric_keys:
            mutations.append(("boundary_zero", {**original_body, numeric_keys[0]: 0}))
            mutations.append(("boundary_negative", {**original_body, numeric_keys[0]: -1}))
        observations = []
        for mutation_name, mutated_body in mutations:
            mutated = response_cache.request(
                url,
                method="POST",
                body=json.dumps(mutated_body),
                headers={
                    "Cache-Control": "no-cache",
                    "Content-Type": "application/json",
                    "X-POST-Mutation": mutation_name,
                },
            )
            if not mutated:
                continue
            diff = variant_diff_summary(baseline, mutated)
            if diff["changed"] or diff["status_changed"] or diff["body_similarity"] < 0.95:
                observations.append({"mutation": mutation_name, **diff})
        if observations:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "observations": observations[:4],
                    "signals": [
                        "post_body_mutation",
                        "status_divergence"
                        if any(o.get("status_changed") for o in observations)
                        else "content_divergence",
                    ],
                }
            )
    findings.sort(key=lambda item: (-len(item["observations"]), item["url"]))
    return findings[:limit]


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
        ]
    return [
        ("json_object", '{"value":"probe"}'),
        ("json_array", '["probe"]'),
    ]
