"""Finding deduplication and correlation utilities.

Contains functions for cross-module deduplication, evidence similarity
comparison, fuzzy URL pattern matching, and finding correlation.
Extracted from intelligence_findings.py for better separation of concerns.
"""

import copy
from difflib import SequenceMatcher
from typing import Any, cast
from urllib.parse import urlparse

from src.analysis.helpers import endpoint_base_key

_VALIDATION_STATE_RANKS: dict[str, int] = {
    "": 0,
    "heuristic_candidate": 1,
    "passive_only": 1,
    "potential_idor": 2,
    "validated": 2,
    "response_similarity_match": 3,
    "active_ready": 4,
    "confirmed": 5,
}

_LIFECYCLE_RANKS: dict[str, int] = {
    "": 0,
    "detected": 1,
    "validated": 2,
    "exploitable": 3,
    "reportable": 4,
}


def _validation_state_rank(value: object) -> int:
    normalized = str(value or "").strip().lower()
    if normalized in _VALIDATION_STATE_RANKS:
        return _VALIDATION_STATE_RANKS[normalized]
    return 1 if normalized else 0


def _lifecycle_state_rank(value: object) -> int:
    return _LIFECYCLE_RANKS.get(str(value or "").strip().lower(), 0)


def _merge_finding_context(target: dict[str, Any], source: dict[str, Any]) -> None:
    target_evidence = dict(target.get("evidence", {}) or {})
    source_evidence = dict(source.get("evidence", {}) or {})

    for key, value in source_evidence.items():
        if key in {"signals", "merged_signals"}:
            continue
        if key not in target_evidence or target_evidence[key] in ("", None, [], {}):
            target_evidence[key] = value

    merged_signals = {
        str(signal)
        for signal in (
            list(target_evidence.get("signals", []))
            + list(target_evidence.get("merged_signals", []))
            + list(source_evidence.get("signals", []))
            + list(source_evidence.get("merged_signals", []))
        )
        if str(signal).strip()
    }
    if merged_signals:
        merged_signal_list = sorted(merged_signals)
        target_evidence["signals"] = merged_signal_list
        target_evidence["merged_signals"] = merged_signal_list

    target_validation_state = (
        str(target.get("validation_state") or target_evidence.get("validation_state") or "")
        .strip()
        .lower()
    )
    source_validation_state = (
        str(source.get("validation_state") or source_evidence.get("validation_state") or "")
        .strip()
        .lower()
    )
    if _validation_state_rank(source_validation_state) > _validation_state_rank(
        target_validation_state
    ):
        target_validation_state = source_validation_state
    if target_validation_state:
        target["validation_state"] = target_validation_state
        target_evidence["validation_state"] = target_validation_state

    target_lifecycle_state = str(target.get("lifecycle_state", "")).strip().lower()
    source_lifecycle_state = str(source.get("lifecycle_state", "")).strip().lower()
    if _lifecycle_state_rank(source_lifecycle_state) > _lifecycle_state_rank(
        target_lifecycle_state
    ):
        target["lifecycle_state"] = source_lifecycle_state

    target_verified = bool(
        target.get("verified")
        or target.get("exploit_verified")
        or target_evidence.get("confirmed")
        or target_evidence.get("validation_confirmed")
    )
    source_verified = bool(
        source.get("verified")
        or source.get("exploit_verified")
        or source_evidence.get("confirmed")
        or source_evidence.get("validation_confirmed")
    )
    if target_verified or source_verified:
        target["verified"] = True
        target_evidence["validation_confirmed"] = True

    target_exploit_verified = bool(
        target.get("exploit_verified")
        or target_evidence.get("confirmed")
        or source.get("exploit_verified")
        or source_evidence.get("confirmed")
    )
    if target_exploit_verified:
        target["exploit_verified"] = True
        target_evidence["confirmed"] = True

    target["evidence"] = target_evidence


def finding_key(item: dict[str, Any]) -> str:
    """Generate a deduplication key for a finding."""
    evidence = item.get("evidence", {}) or {}
    endpoint_base = str(
        evidence.get("endpoint_key")
        or evidence.get("endpoint_base_key")
        or endpoint_base_key(item.get("url", ""))
    )
    return f"{item.get('category', '')}|{endpoint_base}|{item.get('title', '')}"


def dedup_cross_module(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge findings from different modules targeting the same (category, url).

    Groups findings by (category, endpoint_base_key, title) and merges evidence from
    multiple modules into a single finding with a source_modules list.
    """
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for item in findings:
        evidence = item.get("evidence", {}) or {}
        endpoint_base = str(
            evidence.get("endpoint_key")
            or evidence.get("endpoint_base_key")
            or endpoint_base_key(item.get("url", ""))
        )
        key = (item.get("category", ""), endpoint_base, item.get("title", ""))
        groups.setdefault(key, []).append(item)

    merged: list[dict[str, Any]] = []
    for (category, endpoint_base, title), group in groups.items():
        if len(group) == 1:
            item = group[0]
            if "source_modules" not in item:
                item = {**item, "source_modules": [item.get("module", "unknown")]}
            merged.append(item)
            continue

        group.sort(key=lambda x: -x.get("score", 0))
        base = copy.deepcopy(group[0])
        source_modules = [item.get("module", "unknown") for item in group]
        max_confidence = 0.0
        max_score = base.get("score", 0)
        for item in group:
            max_confidence = max(max_confidence, float(item.get("confidence", 0)))
            max_score = max(max_score, item.get("score", 0))
            _merge_finding_context(base, item)

        deduped_source_modules = list(dict.fromkeys(source_modules))
        base["source_modules"] = deduped_source_modules
        base["module_count"] = len(deduped_source_modules)
        base["score"] = max_score
        correlation_bonus = min(0.1 * (len(deduped_source_modules) - 1), 0.25)
        base["confidence"] = round(min(max_confidence + correlation_bonus, 1.0), 2)
        base["correlated_sources"] = (
            deduped_source_modules if len(deduped_source_modules) > 1 else []
        )
        if len(deduped_source_modules) > 1:
            base["explanation"] = (
                f"Detected by {len(deduped_source_modules)} modules ({', '.join(deduped_source_modules[:3])}). "
                + base.get("explanation", "")
            )
            base["explanation"] += (
                f" Confidence boosted by {correlation_bonus:.2f} due to multi-module correlation."
            )
        merged.append(base)

    return merged


def evidence_similarity(a: dict[str, Any], b: dict[str, Any]) -> float:
    """Compute similarity score between two findings based on evidence overlap."""
    url_a = str(a.get("url", "")).strip().lower()
    url_b = str(b.get("url", "")).strip().lower()
    url_sim = SequenceMatcher(None, url_a, url_b).ratio()

    cat_a = str(a.get("category", "")).strip().lower()
    cat_b = str(b.get("category", "")).strip().lower()
    cat_match = 1.0 if cat_a and cat_a == cat_b else 0.0

    title_a = str(a.get("title", "")).strip().lower()
    title_b = str(b.get("title", "")).strip().lower()
    title_sim = SequenceMatcher(None, title_a, title_b).ratio()

    ev_a = a.get("evidence", {}) or {}
    ev_b = b.get("evidence", {}) or {}
    sig_a = {str(s).lower() for s in ev_a.get("signals", [])}
    sig_b = {str(s).lower() for s in ev_b.get("signals", [])}
    sig_sim = len(sig_a & sig_b) / max(len(sig_a | sig_b), 1)

    return round(0.35 * url_sim + 0.25 * cat_match + 0.20 * title_sim + 0.20 * sig_sim, 3)


def dedup_evidence_similarity(
    findings: list[dict[str, Any]], similarity_threshold: float = 0.85
) -> list[dict[str, Any]]:
    """Remove findings with highly similar evidence, keeping the highest-scoring one."""
    if len(findings) < 2:
        return findings

    kept: list[dict[str, Any]] = []
    for item in findings:
        is_duplicate = False
        for idx, existing in enumerate(kept):
            if evidence_similarity(item, existing) >= similarity_threshold:
                prefer_item = item.get("score", 0) > existing.get("score", 0)
                preferred = copy.deepcopy(item if prefer_item else existing)
                other = existing if prefer_item else item
                _merge_finding_context(preferred, other)
                preferred["score"] = max(preferred.get("score", 0), other.get("score", 0))
                preferred["confidence"] = round(
                    max(float(preferred.get("confidence", 0)), float(other.get("confidence", 0))),
                    2,
                )
                kept[idx] = preferred
                is_duplicate = True
                break
        if not is_duplicate:
            kept.append(item)
    return kept


def _url_path_similarity(url_a: str, url_b: str) -> float:
    """Compute similarity between URL paths, ignoring query parameters."""
    pa = urlparse(url_a)
    pb = urlparse(url_b)
    if pa.netloc.lower() != pb.netloc.lower():
        return 0.0
    path_sim = SequenceMatcher(None, pa.path, pb.path).ratio()
    return round(path_sim, 3)


def dedup_fuzzy_url_patterns(
    findings: list[dict[str, Any]], similarity_threshold: float = 0.9
) -> list[dict[str, Any]]:
    """Remove findings with very similar URL patterns, keeping the highest-scoring one.

    Groups findings by category and title, then removes duplicates within
    each group based on URL path similarity.
    """
    if len(findings) < 2:
        return findings

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in findings:
        key = (str(item.get("category", "")).lower(), str(item.get("title", "")).lower())
        groups.setdefault(key, []).append(item)

    kept: list[dict[str, Any]] = []
    for (category, title), group in groups.items():
        if len(group) == 1:
            kept.append(group[0])
            continue

        group.sort(key=lambda x: -x.get("score", 0))
        selected: list[dict[str, Any]] = []
        for item in group:
            is_duplicate = False
            for existing in selected:
                if (
                    _url_path_similarity(item.get("url", ""), existing.get("url", ""))
                    >= similarity_threshold
                ):
                    existing["score"] = max(existing.get("score", 0), item.get("score", 0))
                    existing["confidence"] = round(
                        max(float(existing.get("confidence", 0)), float(item.get("confidence", 0))),
                        2,
                    )
                    _merge_finding_context(existing, item)
                    is_duplicate = True
                    break
            if not is_duplicate:
                selected.append(item)
        kept.extend(selected)

    return kept


def apply_correlation(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply cross-finding correlation to boost confidence for related findings.

    Finds findings that share the same endpoint base key and category,
    then boosts confidence when multiple independent signals agree.
    Also detects cross-category attack chains (e.g., SSRF + IDOR = critical).
    """
    # Group signals by endpoint and category
    endpoint_signals: dict[str, dict[str, list[str]]] = {}
    # Track categories per endpoint for cross-category correlation
    endpoint_categories: dict[str, set[str]] = {}

    for item in findings:
        evidence = item.get("evidence", {}) or {}
        endpoint_base = str(
            evidence.get("endpoint_key")
            or evidence.get("endpoint_base_key")
            or endpoint_base_key(item.get("url", ""))
        )
        if not endpoint_base:
            continue
        cat = str(item.get("category", "")).lower()
        signals = [str(s).lower() for s in evidence.get("signals", [])]
        endpoint_signals.setdefault(endpoint_base, {}).setdefault(cat, []).extend(signals)
        endpoint_categories.setdefault(endpoint_base, set()).add(cat)

    # Define cross-category attack chains
    attack_chains: dict[tuple[str, str], dict[str, object]] = {
        ("ssrf", "idor"): {"name": "SSRF-enabled IDOR", "bonus": 0.15, "severity": "critical"},
        ("ssrf", "authentication_bypass"): {
            "name": "SSRF + Auth Bypass",
            "bonus": 0.15,
            "severity": "critical",
        },
        ("xss", "token_leak"): {"name": "XSS + Token Theft", "bonus": 0.12, "severity": "high"},
        ("csrf", "business_logic"): {
            "name": "CSRF + Logic Manipulation",
            "bonus": 0.12,
            "severity": "high",
        },
        ("file_upload", "authentication_bypass"): {
            "name": "Upload + Auth Bypass",
            "bonus": 0.15,
            "severity": "critical",
        },
        ("cache_poisoning", "xss"): {
            "name": "Cache Poisoning + XSS",
            "bonus": 0.12,
            "severity": "high",
        },
        ("rate_limit", "authentication_bypass"): {
            "name": "Rate Limit Bypass + Auth Bypass",
            "bonus": 0.10,
            "severity": "high",
        },
        ("graphql", "idor"): {"name": "GraphQL IDOR", "bonus": 0.10, "severity": "high"},
        ("oauth", "open_redirect"): {
            "name": "OAuth Redirect Abuse",
            "bonus": 0.12,
            "severity": "high",
        },
        ("ssti", "authentication_bypass"): {
            "name": "SSTI + Auth Bypass",
            "bonus": 0.15,
            "severity": "critical",
        },
    }

    for item in findings:
        evidence = item.get("evidence", {}) or {}
        endpoint_base = str(
            evidence.get("endpoint_key")
            or evidence.get("endpoint_base_key")
            or endpoint_base_key(item.get("url", ""))
        )
        if not endpoint_base:
            continue
        cat = str(item.get("category", "")).lower()
        all_signals = endpoint_signals.get(endpoint_base, {}).get(cat, [])
        unique_signals = set(all_signals)

        # Same-category signal correlation
        if len(unique_signals) >= 3:
            current_conf = float(item.get("confidence", 0))
            bonus = min(0.05 * (len(unique_signals) - 2), 0.15)
            item["confidence"] = round(min(current_conf + bonus, 1.0), 2)
            item["evidence"] = {**evidence, "correlated_signal_count": len(unique_signals)}

        # Cross-category attack chain detection
        endpoint_cats = endpoint_categories.get(endpoint_base, set())
        for other_cat in endpoint_cats:
            if other_cat == cat:
                continue
            chain_key: tuple[str, ...] = tuple(sorted([cat, other_cat]))
            if chain_key in attack_chains:
                chain = attack_chains[chain_key]
                current_conf = float(item.get("confidence", 0))
                item["confidence"] = round(min(current_conf + cast(float, chain["bonus"]), 1.0), 2)
                item["evidence"] = {
                    **evidence,
                    "attack_chain": chain["name"],
                    "attack_chain_categories": sorted([cat, other_cat]),
                    "attack_chain_bonus": chain["bonus"],
                }
                # Upgrade severity if chain detected
                if chain["severity"] == "critical" and item.get("severity") != "critical":
                    item["severity"] = "critical"
                break  # Only apply first chain bonus

    return findings


def deduplicate_findings(
    findings: list[dict[str, Any]], strategy: str = "evidence_url_severity"
) -> list[dict[str, Any]]:
    """Apply multi-strategy deduplication to findings.

    Args:
        findings: List of finding dicts to deduplicate.
        strategy: Deduplication strategy. Currently supports "evidence_url_severity"
                  which applies cross-module dedup, evidence similarity, and
                  fuzzy URL pattern deduplication in sequence.

    Returns:
        Deduplicated list of findings.
    """
    if not findings:
        return findings

    result = dedup_cross_module(findings)
    if strategy == "evidence_url_severity":
        result = dedup_evidence_similarity(result)
        result = dedup_fuzzy_url_patterns(result)
    return result
