"""Response diff engine for mutation-based behavioral testing."""

from difflib import SequenceMatcher
from typing import Any

from src.analysis.helpers import endpoint_signature, is_noise_url
from src.analysis.intelligence.mutation_runtime import build_all_contextual_diff_mutations
from src.analysis.passive.runtime import ResponseCache, normalize_compare_text

from ._diff_utils import _redirect_target, variant_diff_summary


def response_diff_engine(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 16
) -> list[dict[str, Any]]:
    """Test endpoints with contextual mutations and compare responses."""
    diffs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url in priority_urls:
        if len(diffs) >= limit:
            break
        if not url or is_noise_url(url):
            continue
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)
        mutations = build_all_contextual_diff_mutations(url)
        if not mutations:
            continue
        original = response_cache.get(url)
        if not original:
            continue
        for mutation in mutations:
            if len(diffs) >= limit:
                break
            mutated = response_cache.get(mutation["mutated_url"])
            if not mutated:
                continue
            repeated_mutated = response_cache.request(
                mutation["mutated_url"],
                headers={"Cache-Control": "no-cache", "X-Recheck": "1"},
            )
            diff = variant_diff_summary(original, mutated)
            stability_similarity = 1.0
            result_stable = True
            if repeated_mutated:
                repeated_body = repeated_mutated.get("body_text") or ""
                mutated_body = mutated.get("body_text") or ""
                mutated_ct = str(mutated.get("content_type", "")).lower()
                is_json_response = "json" in mutated_ct
                is_html_response = "html" in mutated_ct
                if is_json_response:
                    stability_threshold = 0.88
                elif is_html_response:
                    stability_threshold = 0.80
                else:
                    stability_threshold = 0.95
                stability_similarity = round(
                    SequenceMatcher(
                        None,
                        normalize_compare_text(mutated_body),
                        normalize_compare_text(repeated_body),
                    ).ratio(),
                    3,
                )
                result_stable = (
                    repeated_mutated.get("status_code") == mutated.get("status_code")
                    and _redirect_target(repeated_mutated) == _redirect_target(mutated)
                    and stability_similarity >= stability_threshold
                )
            diffs.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "parameter": mutation["parameter"],
                    "strategy": mutation["strategy"],
                    "mutated_url": mutation["mutated_url"],
                    "original_status": diff["original_status"],
                    "mutated_status": diff["mutated_status"],
                    "original_redirect": _redirect_target(original),
                    "mutated_redirect": _redirect_target(mutated),
                    "body_similarity": diff["body_similarity"],
                    "length_delta": diff["length_delta"],
                    "shared_key_fields": diff["shared_key_fields"],
                    "status_changed": diff["status_changed"],
                    "redirect_changed": diff["redirect_changed"],
                    "content_changed": diff["content_changed"],
                    "changed": diff["changed"],
                    "classification": diff["classification"],
                    "score": diff["score"],
                    "reason": diff["reason"],
                    "structured_diff_available": diff["structured_diff_available"],
                    "new_fields": diff["new_fields"],
                    "missing_fields": diff["missing_fields"],
                    "changed_fields": diff["changed_fields"],
                    "result_stable": result_stable,
                    "stability_similarity": stability_similarity,
                }
            )
    diffs.sort(key=lambda item: (not item["changed"], -int(item.get("score", 0)), item["url"]))
    return diffs
