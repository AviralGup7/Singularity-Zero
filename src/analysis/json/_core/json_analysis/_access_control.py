"""Access boundary tracking and privilege escalation detection."""

from difflib import SequenceMatcher
from typing import Any

from src.analysis.helpers import (
    endpoint_base_key,
    endpoint_signature,
)
from src.analysis.json.support import (
    access_boundary_state,
    is_low_risk_read_candidate,
    mutate_role_url,
)
from src.analysis.passive.runtime import (
    ResponseCache,
    extract_key_fields,
    normalize_compare_text,
)


def privilege_escalation_detector(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 24
) -> list[dict[str, Any]]:
    """Detect privilege escalation via role parameter mutation."""
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not is_low_risk_read_candidate(url):
            continue
        mutation = mutate_role_url(url)
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
        original_status = int(original.get("status_code") or 0)
        mutated_status = int(mutated.get("status_code") or 0)
        if mutated_status >= 400 and similarity >= 0.97:
            continue
        accessible_after_role_change = original_status >= 400 and mutated_status < 400
        shared_key_fields = sorted(
            extract_key_fields(original.get("body_text") or "")
            & extract_key_fields(mutated.get("body_text") or "")
        )
        if (
            not accessible_after_role_change
            and similarity >= 0.96
            and original_status == mutated_status
        ):
            continue
        if not accessible_after_role_change and not shared_key_fields and similarity >= 0.9:
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
                "original_status": original_status,
                "mutated_status": mutated_status,
                "body_similarity": similarity,
                "shared_key_fields": shared_key_fields[:10],
                "accessible_after_role_change": accessible_after_role_change,
                "signals": sorted(
                    {
                        "role_change",
                        "access_gained" if accessible_after_role_change else "",
                        "status_divergence" if original_status != mutated_status else "",
                        "content_divergence" if similarity < 0.9 else "",
                    }
                    - {""}
                ),
            }
        )
    return findings


def access_boundary_tracker(
    responses: list[dict[str, Any]], limit: int = 60
) -> list[dict[str, Any]]:
    """Track access boundary transitions across endpoints."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        grouped.setdefault(endpoint_base_key(url), []).append(response)

    findings: list[dict[str, Any]] = []
    for endpoint_base, items in grouped.items():
        boundary_states = set()
        sample_urls: list[str] = []
        for response in items:
            url = str(response.get("url", "")).strip()
            if not url:
                continue
            sample_urls.append(url)
            boundary_states.add(access_boundary_state(url, response))
        ordered = [state for state in ("public", "private", "admin") if state in boundary_states]
        if len(ordered) < 2:
            continue
        findings.append(
            {
                "url": sample_urls[0],
                "endpoint_key": endpoint_signature(sample_urls[0]),
                "endpoint_base_key": endpoint_base,
                "boundary_transitions": ordered,
                "transition_count": len(ordered) - 1,
                "sample_urls": sample_urls[:6],
                "signals": [
                    f"{ordered[index]}_to_{ordered[index + 1]}" for index in range(len(ordered) - 1)
                ],
            }
        )
    findings.sort(key=lambda item: (-item["transition_count"], item["url"]))
    return findings[:limit]
