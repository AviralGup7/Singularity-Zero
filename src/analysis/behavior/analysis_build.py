"""Behavior analysis builder for controlled variant testing.

Constructs behavior analysis findings by applying controlled mutations
to priority URLs and comparing response differences to detect access
control deviations, flow transitions, and trust boundary shifts.
"""

from typing import Any

from src.analysis.behavior.analysis_support import (
    apply_variant_to_url,
    compare_response_records,
    detect_flow_transition,
    detect_trust_boundary_shift,
    impact_level_for_score,
)
from src.analysis.helpers import (
    REDIRECT_PARAM_NAMES,
    endpoint_base_key,
    ensure_endpoint_key,
    is_auth_flow_endpoint,
    resolve_endpoint_key,
    signal_weight,
)
from src.core.contracts.pipeline import dedup_digest
from src.execution.exploiters.exploit_automation import enrich_behavior_finding


def build_behavior_analysis(
    ranked_priority_urls: list[dict[str, Any]],
    response_cache: Any,
    payload_suggestions: list[dict[str, Any]],
    flow_items: list[dict[str, Any]],
    token_findings: list[dict[str, Any]],
    ssrf_findings: list[dict[str, Any]],
    max_endpoints: int = 12,
    max_variants_per_endpoint: int = 3,
) -> list[dict[str, Any]]:
    """Build behavior analysis findings by testing controlled URL variants.

    For each priority URL, applies payload suggestions and compares responses
    to detect behavioral deviations that may indicate access control issues.

    Args:
        ranked_priority_urls: Prioritized URL list with scores.
        response_cache: ResponseCache for making HTTP requests.
        payload_suggestions: Generated payload suggestions per endpoint.
        flow_items: Flow detection results for URL chaining.
        token_findings: Token leak findings for context.
        ssrf_findings: SSRF candidate findings for context.
        max_endpoints: Maximum endpoints to analyze.
        max_variants_per_endpoint: Maximum variants to test per endpoint.

    Returns:
        List of behavior analysis finding dicts.
    """
    suggestions_by_key = {
        str(item.get("endpoint_key", "")): list(item.get("suggestions", []))
        for item in payload_suggestions
        if item.get("endpoint_key")
    }
    flow_labels_by_url: dict[str, set[str]] = {}
    for item in flow_items:
        label = str(item.get("label", "")).strip()
        for url in item.get("chain", []):
            if not url:
                continue
            flow_labels_by_url.setdefault(str(url), set()).add(label)
    token_endpoint_keys = {
        resolve_endpoint_key(item)
        for item in token_findings
        if item.get("endpoint_key") or item.get("endpoint_base_key")
    }
    ssrf_endpoint_keys = {
        resolve_endpoint_key(item)
        for item in ssrf_findings
        if item.get("endpoint_key") or item.get("endpoint_base_key")
    }

    findings: list[dict[str, Any]] = []
    seen_replays: set[str] = set()
    # Track per-endpoint variant results for intra-run confirmation
    endpoint_variant_results: dict[str, list[dict[str, Any]]] = {}

    for item in ranked_priority_urls[:max_endpoints]:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = ensure_endpoint_key(item, url)
        endpoint_base = str(item.get("endpoint_base_key") or endpoint_base_key(url))
        base_score = int(item.get("score", 0))
        baseline = response_cache.get(url)
        if not baseline:
            continue
        for suggestion in suggestions_by_key.get(endpoint_key, [])[:max_variants_per_endpoint]:
            parameter = str(suggestion.get("parameter", "")).strip().lower()
            variant = str(suggestion.get("variant", "")).strip()
            if not parameter or not variant:
                continue
            mutated_url = apply_variant_to_url(url, parameter, variant)
            if not mutated_url:
                continue
            replay_id = dedup_digest(endpoint_key, parameter, variant, mutated_url)
            if replay_id in seen_replays:
                continue
            seen_replays.add(replay_id)
            mutated = response_cache.get(mutated_url)
            if not mutated:
                continue

            diff = compare_response_records(baseline, mutated)
            flow_transition = detect_flow_transition(
                url, diff["variant_snapshot"]["final_url"], flow_labels_by_url.get(url, set())
            )
            trust_shift = detect_trust_boundary_shift(baseline, mutated, parameter)
            signals = {
                signal
                for signal in (
                    "auth" if is_auth_flow_endpoint(url) or flow_labels_by_url.get(url) else "",
                    "redirect"
                    if parameter in REDIRECT_PARAM_NAMES or diff["redirect_changed"]
                    else "",
                    "token"
                    if parameter in {"token", "state", "session", "jwt"}
                    or endpoint_key in token_endpoint_keys
                    or endpoint_base in token_endpoint_keys
                    else "",
                    "ssrf"
                    if parameter
                    in {
                        "callback",
                        "dest",
                        "destination",
                        "profile",
                        "return_to",
                        "state",
                        "uri",
                        "url",
                    }
                    or endpoint_key in ssrf_endpoint_keys
                    or endpoint_base in ssrf_endpoint_keys
                    else "",
                    "status_change" if diff["status_changed"] else "",
                    "content_change" if diff["content_changed"] else "",
                    "flow_transition" if flow_transition["changed"] else "",
                    "trust_boundary_shift" if trust_shift else "",
                    "access_control"
                    if diff["status_changed"]
                    and diff["original_status"] == 200
                    and diff["mutated_status"] in {401, 403}
                    else "",
                    "business_logic"
                    if diff["status_changed"]
                    and diff["original_status"] != diff["mutated_status"]
                    and diff["mutated_status"] not in {400, 401, 403, 404, 500}
                    else "",
                )
                if signal
            }
            impact_score = base_score + sum(signal_weight(signal) for signal in signals)
            if trust_shift:
                impact_score += 4
            if diff["redirect_changed"]:
                impact_score += 2
            if len({"auth", "redirect", "token"} & signals) >= 2:
                impact_score += 4
            if "access_control" in signals:
                impact_score += 3
            if "business_logic" in signals:
                impact_score += 2
            meaningful = bool(diff["changed"] or flow_transition["changed"] or trust_shift)

            finding = {
                "id": replay_id,
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base,
                "parameter": parameter,
                "variant": variant,
                "variant_reason": str(suggestion.get("reason", "")).strip(),
                "mutated_request_url": mutated_url,
                "base_score": base_score,
                "signals": sorted(signals),
                "multi_signal_overlap": sorted({"auth", "redirect", "token"} & signals),
                "meaningful_difference": meaningful,
                "impact_score": impact_score,
                "impact_level": impact_level_for_score(impact_score, trust_shift, len(signals)),
                "trust_boundary_shift": trust_shift,
                "flow_transition": flow_transition,
                "diff": diff,
                "evidence": {
                    "baseline_snapshot": diff["baseline_snapshot"],
                    "variant_snapshot": diff["variant_snapshot"],
                    "diff_summary": {
                        "status_changed": diff["status_changed"],
                        "redirect_changed": diff["redirect_changed"],
                        "content_changed": diff["content_changed"],
                        "body_similarity": diff["body_similarity"],
                        "length_delta": diff["length_delta"],
                    },
                },
                "request_context": {
                    "method": "GET",
                    "baseline_url": diff["baseline_snapshot"]["requested_url"],
                    "mutated_url": mutated_url,
                    "parameter": parameter,
                    "variant": variant,
                },
                "replay": {
                    "id": replay_id,
                    "target_url": mutated_url,
                },
                "reproducible": False,
                "confirmed": False,
                "repeat_count": 1,
                "stability": "candidate",
            }

            # Track for intra-run confirmation
            endpoint_variant_results.setdefault(endpoint_key, []).append(
                {
                    "finding": finding,
                    "signals": signals,
                    "meaningful": meaningful,
                    "trust_shift": trust_shift,
                    "status_changed": diff["status_changed"],
                    "original_status": diff["original_status"],
                    "mutated_status": diff["mutated_status"],
                }
            )

            findings.append(enrich_behavior_finding(finding))

    # Post-processing: intra-run confirmation for endpoints with consistent variants
    for endpoint_key, variants in endpoint_variant_results.items():
        if len(variants) < 2:
            continue

        # Count how many variants produced meaningful differences
        meaningful_count = sum(1 for v in variants if v["meaningful"])
        status_change_count = sum(1 for v in variants if v["status_changed"])
        trust_shift_count = sum(1 for v in variants if v["trust_shift"])

        # Intra-run confirmation: 2+ variants with consistent behavior
        if meaningful_count >= 2:
            for v in variants:
                if v["meaningful"]:
                    v["finding"]["reproducible"] = True
                    v["finding"]["stability"] = "intra_run_confirmed"
                    v["finding"]["repeat_count"] = meaningful_count
                    # Bonus for intra-run confirmation
                    v["finding"]["impact_score"] += 2
                    v["finding"]["impact_level"] = impact_level_for_score(
                        v["finding"]["impact_score"],
                        v["trust_shift"],
                        len(v["signals"]),
                    )

        # Strong confirmation: 2+ status changes or trust shifts
        if status_change_count >= 2 or trust_shift_count >= 1:
            for v in variants:
                if v["status_changed"] or v["trust_shift"]:
                    v["finding"]["confirmed"] = True
                    v["finding"]["stability"] = "confirmed"
                    v["finding"]["impact_score"] += 3

    findings.sort(
        key=lambda entry: (
            not entry["meaningful_difference"],
            entry["impact_level"] != "high",
            not entry["trust_boundary_shift"],
            not entry["confirmed"],  # Confirmed findings rank higher
            not entry["reproducible"],  # Reproducible findings rank higher
            -entry["impact_score"],
            entry["url"],
        )
    )
    return findings[:40]
