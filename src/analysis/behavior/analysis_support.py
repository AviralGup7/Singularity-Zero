"""Behavior analysis support utilities for response comparison and variant testing.

Provides functions for comparing HTTP responses, applying URL mutations,
detecting flow transitions, trust boundary shifts, and annotating behavior
history across pipeline runs.
"""

from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.behavior.artifacts import load_plugin_artifact
from src.analysis.helpers import (
    REDIRECT_PARAM_NAMES,
    ensure_endpoint_key,
    extract_host_candidate,
    is_auth_flow_endpoint,
    same_host_family,
)
from src.analysis.passive.patterns import JWT_RE
from src.analysis.response.filter_rules import classify_response_delta
from src.analysis.text_utils import extract_key_fields, normalize_compare_text
from src.recon.common import normalize_url

FLOW_STAGE_LABELS = {
    0: "access",
    1: "auth",
    2: "oauth",
    3: "redirect",
    4: "post_auth",
}


def annotate_behavior_history(
    previous_run: Path | None, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Annotate findings with reproducibility and confirmation status.

    Supports both cross-run confirmation (when previous_run is provided)
    and intra-run confirmation through multi-mutation consistency analysis.
    A finding is confirmed when:
    - Cross-run: Same behavior observed in 2+ pipeline runs
    - Intra-run: Multiple mutation variants produce consistent response deltas

    Args:
        previous_run: Path to previous run's artifact directory.
        findings: List of behavior analysis findings to annotate.

    Returns:
        Annotated findings with reproducibility, confirmation, and confidence.
    """
    previous_by_key: dict[str, dict[str, Any]] = {}
    if previous_run is not None:
        for item in load_plugin_artifact(previous_run, "behavior_analysis_layer"):
            if not isinstance(item, dict):
                continue
            previous_by_key[behavior_history_key(item)] = item

    annotated = []
    for item in findings:
        key = behavior_history_key(item)
        previous = previous_by_key.get(key, {})
        previous_diff = previous.get("diff", {}) if isinstance(previous, dict) else {}
        current_diff = item.get("diff", {})

        cross_run_reproducible = bool(
            previous
            and previous.get("meaningful_difference")
            and item.get("meaningful_difference")
            and previous_diff.get("status_changed") == current_diff.get("status_changed")
            and previous_diff.get("redirect_changed") == current_diff.get("redirect_changed")
            and previous.get("trust_boundary_shift") == item.get("trust_boundary_shift")
        )

        intra_run_confirmed = _check_intra_run_consistency(item)

        reproducible = cross_run_reproducible or intra_run_confirmed
        repeat_count = int(previous.get("repeat_count", 1)) + 1 if cross_run_reproducible else 1
        if intra_run_confirmed and not cross_run_reproducible:
            repeat_count = max(repeat_count, int(item.get("mutation_consistency_count", 1)))

        confirmed = (
            reproducible and repeat_count >= 2 and item.get("impact_level") in {"high", "medium"}
        )
        stability = "confirmed" if confirmed else "reproducible" if reproducible else "candidate"
        confidence = 0.58
        if item.get("meaningful_difference"):
            confidence += 0.12
        if item.get("trust_boundary_shift"):
            confidence += 0.08
        if cross_run_reproducible:
            confidence += 0.10
        if intra_run_confirmed:
            confidence += 0.08
        if confirmed:
            confidence += 0.07
        if item.get("diff", {}).get("body_similarity", 1.0) <= 0.55:
            confidence += 0.05
        annotated.append(
            {
                **item,
                "reproducible": reproducible,
                "confirmed": confirmed,
                "cross_run_reproducible": cross_run_reproducible,
                "intra_run_confirmed": intra_run_confirmed,
                "repeat_count": repeat_count,
                "stability": stability,
                "confidence": round(min(confidence, 0.97), 2),
            }
        )
    return annotated


def _check_intra_run_consistency(item: dict[str, Any]) -> bool:
    """Check if a finding is confirmed through intra-run mutation consistency.

    When multiple mutation variants of the same endpoint produce consistent
    response deltas (same status change pattern, similar body changes),
    the finding is considered confirmed within a single run.

    Args:
        item: Finding dict that may contain mutation comparison results.

    Returns:
        True if intra-run consistency confirms the finding.
    """
    comparison = item.get("comparison") or {}
    if not comparison:
        return False

    all_results = comparison.get("all_results", [])
    if len(all_results) < 2:
        return False

    mutations_confirmed = comparison.get("mutations_confirmed", 0)
    if mutations_confirmed >= 2:
        item["mutation_consistency_count"] = mutations_confirmed
        return True

    consistent_status_changes = []
    for result in all_results:
        if result.get("confirmed"):
            consistent_status_changes.append(result)

    if len(consistent_status_changes) >= 2:
        item["mutation_consistency_count"] = len(consistent_status_changes)
        return True

    return False


def compare_response_records(original: dict[str, Any], mutated: dict[str, Any]) -> dict[str, Any]:
    original_body = original.get("body_text") or ""
    mutated_body = mutated.get("body_text") or ""
    similarity = round(
        SequenceMatcher(
            None, normalize_compare_text(original_body), normalize_compare_text(mutated_body)
        ).ratio(),
        3,
    )
    original_snapshot = snapshot_from_response(original)
    variant_snapshot = snapshot_from_response(mutated)
    status_changed = original_snapshot["status_code"] != variant_snapshot["status_code"]
    redirect_changed = original_snapshot["final_url"] != variant_snapshot["final_url"]
    content_changed = similarity < 0.96 or abs(len(original_body) - len(mutated_body)) > max(
        40, int(max(len(original_body), 1) * 0.1)
    )
    response_filter = classify_response_delta(
        original_status=original_snapshot["status_code"],
        mutated_status=variant_snapshot["status_code"],
        body_similarity=similarity,
        length_delta=abs(len(original_body) - len(mutated_body)),
        redirect_changed=redirect_changed,
    )
    return {
        "status_changed": status_changed,
        "redirect_changed": redirect_changed,
        "content_changed": content_changed,
        "changed": bool(response_filter["include"]),
        "classification": response_filter["classification"],
        "score": int(cast(float, response_filter["score"])),
        "reason": response_filter["reason"],
        "body_similarity": similarity,
        "length_delta": abs(len(original_body) - len(mutated_body)),
        "shared_key_fields": sorted(
            extract_key_fields(original_body) & extract_key_fields(mutated_body)
        )[:12],
        "original_status": original_snapshot["status_code"],
        "mutated_status": variant_snapshot["status_code"],
        "baseline_snapshot": original_snapshot,
        "variant_snapshot": variant_snapshot,
    }


def snapshot_from_response(response: dict[str, Any]) -> dict[str, Any]:
    requested_url = normalize_url(str(response.get("requested_url") or response.get("url") or ""))
    final_url = normalize_url(str(response.get("url") or requested_url))
    redirect_chain = list(response.get("redirect_chain") or [requested_url])
    if redirect_chain[-1:] != [final_url]:
        redirect_chain.append(final_url)
    body = response.get("body_text") or ""
    return {
        "requested_url": requested_url,
        "final_url": final_url,
        "status_code": response.get("status_code"),
        "redirect_chain": redirect_chain,
        "redirect_count": max(len(redirect_chain) - 1, 0),
        "response_length": int(response.get("body_length", len(body))),
        "content_type": response.get("content_type", ""),
        "key_patterns": key_patterns_for_response(response),
    }


def apply_variant_to_url(url: str, parameter: str, variant: str) -> str:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated = []
    replaced = False
    for key, value in query_pairs:
        if key.strip().lower() == parameter:
            updated.append((key, variant))
            replaced = True
        else:
            updated.append((key, value))
    if not replaced:
        return ""
    return normalize_url(urlunparse(parsed._replace(query=urlencode(updated, doseq=True))))


def detect_flow_transition(
    source_url: str, destination_url: str, source_flow_labels: set[str]
) -> dict[str, Any]:
    source_stage = flow_stage_label(source_url)
    destination_stage = flow_stage_label(destination_url)
    source_labels = sorted(source_flow_labels)
    return {
        "from": source_stage,
        "to": destination_stage,
        "changed": bool(source_stage and destination_stage and source_stage != destination_stage),
        "source_flow_labels": source_labels,
    }


def detect_trust_boundary_shift(
    original: dict[str, Any], mutated: dict[str, Any], parameter: str
) -> bool:
    if parameter not in REDIRECT_PARAM_NAMES and parameter not in {
        "callback",
        "dest",
        "destination",
        "uri",
        "url",
    }:
        return False
    original_host = urlparse(
        str(original.get("url", "") or original.get("requested_url", ""))
    ).netloc.lower()
    mutated_host = urlparse(
        str(mutated.get("url", "") or mutated.get("requested_url", ""))
    ).netloc.lower()
    if not original_host or not mutated_host:
        return False
    if same_host_family(original_host, mutated_host):
        return False
    target_host = extract_host_candidate(
        mutated.get("requested_url", "")
    ) or extract_host_candidate(mutated.get("url", ""))
    return bool(target_host and not same_host_family(original_host, target_host))


def behavior_history_key(item: dict[str, Any]) -> str:
    endpoint_key = ensure_endpoint_key(item, str(item.get("url", "")))
    return f"{endpoint_key}|{item.get('parameter', '')}|{item.get('variant', '')}"


def flow_stage_label(url: str) -> str:
    lowered = str(url or "").lower()
    if "/access" in lowered:
        return FLOW_STAGE_LABELS[0]
    if any(token in lowered for token in ("/auth", "/login", "/signin")):
        return FLOW_STAGE_LABELS[1]
    if "/oauth" in lowered or any(
        name in {"profile", "return_to", "state"}
        for name, _ in parse_qsl(urlparse(str(url or "")).query, keep_blank_values=True)
    ):
        return FLOW_STAGE_LABELS[2]
    if any(
        name in REDIRECT_PARAM_NAMES
        for name, _ in parse_qsl(urlparse(str(url or "")).query, keep_blank_values=True)
    ):
        return FLOW_STAGE_LABELS[3]
    if is_auth_flow_endpoint(str(url or "")):
        return FLOW_STAGE_LABELS[4]
    return ""


def impact_level_for_score(score: int, trust_shift: bool, signal_count: int) -> str:
    if score >= 18 or trust_shift or signal_count >= 4:
        return "high"
    if score >= 10 or signal_count >= 2:
        return "medium"
    return "low"


def key_patterns_for_response(response: dict[str, Any]) -> list[str]:
    patterns = []
    body = response.get("body_text") or ""
    if JWT_RE.search(body):
        patterns.append("jwt_like_token")
    if any(token in body.lower() for token in ("oauth", "signin", "login", "session")):
        patterns.append("auth_keyword")
    if extract_key_fields(body):
        patterns.append("keyed_response")
    final_url = str(response.get("url", "") or response.get("requested_url", ""))
    if final_url and final_url != str(response.get("requested_url", "") or ""):
        patterns.append("redirect_followed")
    return patterns
