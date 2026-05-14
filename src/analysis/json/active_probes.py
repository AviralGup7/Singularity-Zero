"""Active probe functions for JSON analysis.

Contains functions that actively probe endpoints with mutated requests:
state transitions, parameter dependencies, flow integrity, pagination walking,
and filter parameter fuzzing.
Extracted from json_analysis.py for better separation of concerns.
"""

from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import (
    decode_candidate_value,
    endpoint_base_key,
    endpoint_signature,
    meaningful_query_pairs,
)
from src.analysis.json.support import (
    DEPENDENCY_PARAM_NAMES,
    FILTER_MUTATIONS,
)
from src.analysis.json.support import (
    flow_stage_hint as _flow_stage_hint,
)
from src.analysis.json.support import (
    mutate_dependency_urls as _mutate_dependency_urls,
)
from src.analysis.json.support import (
    mutate_pagination_url as _mutate_pagination_url,
)
from src.analysis.json.support import (
    mutate_state_url as _mutate_state_url,
)
from src.analysis.passive.runtime import (
    ResponseCache,
    extract_key_fields,
    normalize_compare_text,
)
from src.recon.common import normalize_url


def state_transition_analyzer(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 24
) -> list[dict[str, Any]]:
    """Analyze state parameter transitions for integrity issues."""
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        mutation = _mutate_state_url(url)
        if not mutation:
            continue
        original = response_cache.get(url)
        mutated = response_cache.request(
            mutation["mutated_url"], headers={"Cache-Control": "no-cache"}
        )
        if not original or not mutated:
            continue
        similarity = round(
            SequenceMatcher(
                None,
                normalize_compare_text(original.get("body_text") or ""),
                normalize_compare_text(mutated.get("body_text") or ""),
            ).ratio(),
            3,
        )
        status_changed = original.get("status_code") != mutated.get("status_code")
        if not status_changed and similarity >= 0.97:
            continue
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "parameter": mutation["parameter"],
                "original_value": mutation["original_value"],
                "mutated_value": mutation["mutated_value"],
                "mutated_url": mutation["mutated_url"],
                "original_status": original.get("status_code"),
                "mutated_status": mutated.get("status_code"),
                "body_similarity": similarity,
                "state_mismatch": status_changed or similarity < 0.8,
            }
        )
    return findings


def parameter_dependency_tracker(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 30
) -> list[dict[str, Any]]:
    """Track parameter dependencies across endpoints."""
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        params = [name for name, _ in meaningful_query_pairs(url)]
        dependencies = sorted({name for name in params if name in DEPENDENCY_PARAM_NAMES})
        if len(dependencies) < 2:
            continue
        original = response_cache.get(url)
        if not original:
            continue
        mutations = _mutate_dependency_urls(url)
        observed = []
        for mutation in mutations[:3]:
            mutated = response_cache.request(
                mutation["mutated_url"], headers={"Cache-Control": "no-cache"}
            )
            if not mutated:
                continue
            similarity = round(
                SequenceMatcher(
                    None,
                    normalize_compare_text(original.get("body_text") or ""),
                    normalize_compare_text(mutated.get("body_text") or ""),
                ).ratio(),
                3,
            )
            if original.get("status_code") != mutated.get("status_code") or similarity < 0.97:
                observed.append(
                    {
                        "parameter": mutation["parameter"],
                        "original_value": mutation["original_value"],
                        "mutated_value": mutation["mutated_value"],
                        "mutated_status": mutated.get("status_code"),
                        "body_similarity": similarity,
                    }
                )
        if observed:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "dependent_parameters": dependencies,
                    "observed_mutations": observed[:6],
                    "dependency_count": len(dependencies),
                }
            )
        if len(findings) >= limit:
            break
    findings.sort(key=lambda item: (-item["dependency_count"], item["url"]))
    return findings


def flow_integrity_checker(
    flow_items: list[dict[str, Any]], limit: int = 40
) -> list[dict[str, Any]]:
    """Check flow integrity for sequence inconsistencies."""
    findings: list[dict[str, Any]] = []
    for item in flow_items:
        chain = [str(value).strip() for value in item.get("chain", []) if str(value).strip()]
        if len(chain) < 2:
            continue
        stages = [_flow_stage_hint(url) for url in chain]
        missing_sequence = any(
            later and earlier and later < earlier for earlier, later in zip(stages, stages[1:])
        )
        if not missing_sequence and len(set(stages)) == len(stages):
            continue
        findings.append(
            {
                "url": chain[0],
                "endpoint_key": endpoint_signature(chain[0]),
                "endpoint_base_key": endpoint_base_key(chain[0]),
                "label": item.get("label", "flow"),
                "chain": chain[:8],
                "stages": stages[:8],
                "step_skipping_possible": missing_sequence,
                "signals": ["flow_order_inconsistency"]
                if missing_sequence
                else ["repeated_stage_transition"],
            }
        )
    return findings[:limit]


def pagination_walker(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 24
) -> list[dict[str, Any]]:
    """Walk pagination parameters to detect data exposure."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url in priority_urls:
        if len(findings) >= limit:
            break
        mutation = _mutate_pagination_url(url)
        if not mutation or mutation["mutated_url"] in seen:
            continue
        seen.add(mutation["mutated_url"])
        original = response_cache.get(url)
        mutated = response_cache.request(
            mutation["mutated_url"], headers={"Cache-Control": "no-cache"}
        )
        if not original or not mutated:
            continue
        original_body = original.get("body_text") or ""
        mutated_body = mutated.get("body_text") or ""
        body_similarity = round(
            SequenceMatcher(
                None, normalize_compare_text(original_body), normalize_compare_text(mutated_body)
            ).ratio(),
            3,
        )
        length_delta = abs(len(original_body) - len(mutated_body))
        if (
            original.get("status_code") != mutated.get("status_code")
            or length_delta > 40
            or body_similarity < 0.96
        ):
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "parameter": mutation["parameter"],
                    "original_value": mutation["original_value"],
                    "mutated_value": mutation["mutated_value"],
                    "mutated_url": mutation["mutated_url"],
                    "original_status": original.get("status_code"),
                    "mutated_status": mutated.get("status_code"),
                    "body_similarity": body_similarity,
                    "length_delta": length_delta,
                }
            )
    return findings


def filter_parameter_fuzzer(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 24
) -> list[dict[str, Any]]:
    """Fuzz filter parameters to detect hidden states, roles, and global views."""
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue
        original = response_cache.get(url)
        if not original:
            continue
        original_body = original.get("body_text") or ""
        original_key_fields = extract_key_fields(original_body)
        url_findings: list[dict[str, Any]] = []
        for index, (key, value) in enumerate(query_pairs):
            lowered = key.strip().lower()
            if lowered not in FILTER_MUTATIONS:
                continue
            mutation_value = FILTER_MUTATIONS[lowered]
            updated = list(query_pairs)
            updated[index] = (key, mutation_value)
            mutated_url = normalize_url(
                urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
            )
            mutated = response_cache.request(mutated_url, headers={"Cache-Control": "no-cache"})
            if not mutated:
                continue
            mutated_body = mutated.get("body_text") or ""
            similarity = round(
                SequenceMatcher(
                    None,
                    normalize_compare_text(original_body),
                    normalize_compare_text(mutated_body),
                ).ratio(),
                3,
            )
            mutated_key_fields = extract_key_fields(mutated_body)
            new_fields = sorted(mutated_key_fields - original_key_fields)[:10]
            status_changed = original.get("status_code") != mutated.get("status_code")
            if (
                original.get("status_code") == mutated.get("status_code")
                and similarity >= 0.98
                and not new_fields
            ):
                continue
            signals = ["filter_parameter_fuzz"]
            if status_changed:
                signals.append("status_change_on_filter")
            if new_fields:
                signals.append("new_fields_exposed")
            if similarity < 0.8:
                signals.append("significant_content_change")
            if lowered in {
                "role",
                "roles",
                "is_admin",
                "admin",
                "permissions",
                "permission",
                "access_level",
                "user_role",
            }:
                signals.append("role_filter_manipulation")
            if lowered in {
                "include_deleted",
                "show_deleted",
                "show_archived",
                "show_hidden",
                "show_inactive",
            }:
                signals.append("hidden_data_exposure")
            if (
                lowered in {"scope", "tenant", "organization", "org_id", "team", "group"}
                and mutation_value == "global"
            ):
                signals.append("global_scope_filter")
            if (
                lowered in {"limit", "max_results", "page_size"}
                and mutation_value.isdigit()
                and int(mutation_value) > 10000
            ):
                signals.append("pagination_bypass")
            url_findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "parameter": lowered,
                    "original_value": decode_candidate_value(value),
                    "mutated_value": mutation_value,
                    "mutated_url": mutated_url,
                    "original_status": original.get("status_code"),
                    "mutated_status": mutated.get("status_code"),
                    "body_similarity": similarity,
                    "new_fields": new_fields,
                    "signals": sorted(signals),
                }
            )
        url_findings.sort(
            key=lambda item: (
                0
                if any(
                    s in item["signals"]
                    for s in (
                        "role_filter_manipulation",
                        "global_scope_filter",
                        "pagination_bypass",
                    )
                )
                else 1,
                item["body_similarity"],
            )
        )
        findings.extend(url_findings[:3])
    findings.sort(
        key=lambda item: (
            0
            if any(
                s in item["signals"]
                for s in (
                    "role_filter_manipulation",
                    "global_scope_filter",
                    "pagination_bypass",
                    "hidden_data_exposure",
                )
            )
            else 1,
            item["body_similarity"],
            item["url"],
        )
    )
    return findings[:limit]
