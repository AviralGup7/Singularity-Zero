"""Orchestrator for merging findings from all analysis modules."""

import copy
from typing import Any

from src.analysis.helpers import resolve_endpoint_key
from src.intelligence.severity_model import enrich_findings_with_model_severity

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

    # Fill missing evidence fields without overwriting populated values from the primary finding.
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

    # Bug #40: Allow downgrade when source explicitly contradicts target's
    # validation state.  Previously, validation_state only moved upward,
    # creating a one-way promotion where false confirmations became permanent.
    # Now, if the source explicitly provides a contradictory state (e.g.,
    # source has evidence of false_positive while target is confirmed),
    # and the source's signals provide new information (not just a subset),
    # allow the downgrade.
    target_rank = _validation_state_rank(target_validation_state)
    source_rank = _validation_state_rank(source_validation_state)
    if source_rank > target_rank:
        target_validation_state = source_validation_state
    elif source_rank < target_rank and source_validation_state:
        # Allow downgrade only when source explicitly contradicts AND brings
        # new signal evidence (not just missing data).
        source_signals = set(
            str(s).lower() for s in source_evidence.get("signals", [])
        )
        target_signals = set(
            str(s).lower() for s in target_evidence.get("signals", [])
        )
        # Source brings new signals that target didn't have — it has
        # independent observation power, so its contradictory state matters.
        has_new_evidence = bool(source_signals - target_signals)
        explicit_contradiction = source_validation_state in (
            "false_positive", "heuristic_candidate", ""
        )
        if has_new_evidence and explicit_contradiction:
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


def _dedup_cross_module(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge findings from different modules targeting the same (category, url).

    Bug #39: Correlation bonus now accounts for signal overlap between modules.
    When multiple modules operate on the same underlying response, their signals
    share bias.  The bonus is scaled down by a factor proportional to the
    average pairwise signal overlap so that shared evidence does not inflate
    confidence beyond what truly independent corroboration would justify.
    """
    from src.analysis.helpers import endpoint_base_key

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
    for group in groups.values():
        if len(group) == 1:
            item = copy.deepcopy(group[0])
            if "source_modules" not in item:
                item["source_modules"] = [item.get("module", "unknown")]
            merged.append(item)
            continue

        group.sort(key=lambda x: -x.get("score", 0))
        base = copy.deepcopy(group[0])
        source_modules: list[str] = []
        max_confidence = 0.0
        max_score = base.get("score", 0)
        # Collect per-module signal sets for overlap analysis
        module_signal_sets: list[set[str]] = []
        for item in group:
            source_modules.append(str(item.get("module", "unknown")))
            max_confidence = max(max_confidence, float(item.get("confidence", 0)))
            max_score = max(max_score, item.get("score", 0))
            _merge_finding_context(base, item)
            item_signals = set(
                str(s).lower()
                for s in ((item.get("evidence") or {}).get("signals") or [])
            )
            module_signal_sets.append(item_signals)

        source_modules = list(dict.fromkeys(source_modules))
        base["source_modules"] = source_modules
        base["module_count"] = len(source_modules)
        base["score"] = max_score

        # Bug #39: Compute average pairwise signal overlap to penalize
        # correlation bonus when modules share underlying evidence.
        n = len(source_modules)
        raw_bonus = 0.1 * (n - 1)
        if n >= 2 and all(sigs for sigs in module_signal_sets):
            overlap_sum = 0.0
            pair_count = 0
            for i in range(n):
                for j in range(i + 1, n):
                    sig_a = module_signal_sets[i]
                    sig_b = module_signal_sets[j]
                    if sig_a or sig_b:
                        overlap = len(sig_a & sig_b) / max(len(sig_a | sig_b), 1)
                        overlap_sum += overlap
                        pair_count += 1
            avg_overlap = overlap_sum / max(pair_count, 1)
            # Independence factor: 1.0 = fully independent, 0.0 = identical signals
            independence = max(0.0, 1.0 - avg_overlap)
            correlation_bonus = min(raw_bonus * independence, 0.25)
        else:
            correlation_bonus = min(raw_bonus, 0.25)

        base["confidence"] = round(min(max_confidence + correlation_bonus, 1.0), 2)
        base["correlated_sources"] = source_modules if len(source_modules) > 1 else []
        if len(source_modules) > 1:
            base["explanation"] = (
                f"Detected by {len(source_modules)} modules ({', '.join(source_modules[:3])}). "
                + base.get("explanation", "")
            )
            base["explanation"] += (
                f" Confidence boosted by {correlation_bonus:.2f} due to multi-module correlation."
            )
        merged.append(base)

    return merged


def _evidence_similarity(a: dict[str, Any], b: dict[str, Any]) -> float:
    """Compute similarity score between two findings' evidence (0.0-1.0).

    Bug #41: Added title semantic guard.  Two findings with semantically
    different titles (e.g. "IDOR" vs "Authorization bypass") represent
    distinct security issues even if their signals overlap.  The title
    similarity component is now capped at 0.3 when the titles share fewer
    than 40% of their words, preventing high signal overlap from
    compensating for a title mismatch.
    """
    from src.analysis.helpers import endpoint_base_key

    signals_a = set(str(s).lower() for s in (a.get("evidence", {}) or {}).get("signals", []))
    signals_b = set(str(s).lower() for s in (b.get("evidence", {}) or {}).get("signals", []))

    if not signals_a and not signals_b:
        return 1.0
    if not signals_a or not signals_b:
        return 0.0

    signal_sim = len(signals_a & signals_b) / max(len(signals_a | signals_b), 1)
    score_a = a.get("score", 0)
    score_b = b.get("score", 0)
    max_score = max(score_a, score_b, 1)
    score_sim = 1.0 - abs(score_a - score_b) / max_score
    severity_match = 1.0 if a.get("severity") == b.get("severity") else 0.5
    url_a = str(a.get("url", "")).strip()
    url_b = str(b.get("url", "")).strip()
    base_a = endpoint_base_key(url_a)
    base_b = endpoint_base_key(url_b)
    url_sim = 1.0 if base_a == base_b else 0.3
    title_a = set(str(a.get("title", "")).lower().split())
    title_b = set(str(b.get("title", "")).lower().split())
    if title_a and title_b:
        title_jaccard = len(title_a & title_b) / max(len(title_a | title_b), 1)
        title_sim = title_jaccard
    else:
        title_sim = 1.0 if a.get("title") == b.get("title") else 0.5

    # Bug #41: Title semantic guard — if titles share fewer than 40% of
    # words, cap the title similarity contribution to prevent high signal
    # overlap from masking a genuinely different vulnerability type.
    if title_a and title_b:
        title_overlap_ratio = len(title_a & title_b) / max(len(title_a | title_b), 1)
        if title_overlap_ratio < 0.4:
            title_sim = min(title_sim, 0.3)

    result = float(
        signal_sim * 0.35
        + score_sim * 0.15
        + severity_match * 0.1
        + url_sim * 0.25
        + title_sim * 0.15
    )
    return round(result, 2)


def _dedup_evidence_similarity(
    findings: list[dict[str, Any]], similarity_threshold: float = 0.85
) -> list[dict[str, Any]]:
    """Merge findings with nearly identical evidence on the same endpoint."""
    from src.analysis.helpers import endpoint_base_key

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in findings:
        endpoint_base = str(
            item.get("evidence", {}).get("endpoint_base_key")
            or endpoint_base_key(item.get("url", ""))
        )
        key = (item.get("category", ""), endpoint_base)
        groups.setdefault(key, []).append(item)

    deduped: list[dict[str, Any]] = []
    for group in groups.values():
        if len(group) == 1:
            deduped.append(group[0])
            continue

        group.sort(key=lambda x: -x.get("score", 0))
        kept: list[dict[str, Any]] = []
        merged_into_kept: set[int] = set()

        for i, candidate in enumerate(group):
            if i in merged_into_kept:
                continue
            merged = False
            for keeper in kept:
                similarity = _evidence_similarity(candidate, keeper)
                if similarity >= similarity_threshold:
                    keeper_modules = keeper.get("source_modules", [keeper.get("module", "unknown")])
                    candidate_modules = candidate.get(
                        "source_modules", [candidate.get("module", "unknown")]
                    )
                    all_modules = list(dict.fromkeys(keeper_modules + candidate_modules))
                    keeper["source_modules"] = all_modules
                    keeper["module_count"] = len(all_modules)
                    keeper["score"] = max(keeper.get("score", 0), candidate.get("score", 0))
                    keeper["confidence"] = round(
                        max(
                            float(keeper.get("confidence", 0)),
                            float(candidate.get("confidence", 0)),
                        ),
                        2,
                    )
                    _merge_finding_context(keeper, candidate)
                    merged_into_kept.add(i)
                    merged = True
                    break
            if not merged:
                kept.append(candidate)
        deduped.extend(kept)
    return deduped


def _dedup_fuzzy_url_patterns(
    findings: list[dict[str, Any]], similarity_threshold: float = 0.9
) -> list[dict[str, Any]]:
    """Merge findings on URLs that differ only by query parameters.

    Bug #42: Raised parameter overlap threshold and increased sample_urls
    cap.  Previously, URLs differing by security-relevant parameters (e.g.,
    ?id= vs ?admin=) were merged because the Jaccard overlap of a single
    shared parameter name exceeded 0.5.  Now requires 0.8+ overlap AND
    ensures the parameter *names* are semantically similar (not just
    sharing one common param among many unique ones).  The sample_urls cap
    is raised from 5 to 15 to preserve attack surface breadth for reports.
    """
    from urllib.parse import parse_qsl, urlparse

    from src.analysis.helpers import endpoint_base_key

    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for item in findings:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        base_key = endpoint_base_key(url)
        category = str(item.get("category", "")).strip()
        module = str(item.get("module", "")).strip()
        key = (category, module, base_key)
        groups.setdefault(key, []).append(item)

    deduped: list[dict[str, Any]] = []
    for group in groups.values():
        if len(group) == 1:
            deduped.append(group[0])
            continue

        group.sort(key=lambda x: -x.get("score", 0))
        kept: list[dict[str, Any]] = []
        merged_indices: set[int] = set()

        for i, candidate in enumerate(group):
            if i in merged_indices:
                continue
            merged = False
            for keeper in kept:
                candidate_url = str(candidate.get("url", "")).strip()
                keeper_url = str(keeper.get("url", "")).strip()
                candidate_parsed = urlparse(candidate_url)
                keeper_parsed = urlparse(keeper_url)

                if (
                    candidate_parsed.scheme == keeper_parsed.scheme
                    and candidate_parsed.netloc == keeper_parsed.netloc
                    and candidate_parsed.path == keeper_parsed.path
                ):
                    candidate_params = set(k for k, _ in parse_qsl(candidate_parsed.query))
                    keeper_params = set(k for k, _ in parse_qsl(keeper_parsed.query))

                    if not candidate_params and not keeper_params:
                        # Both have no query params — same URL, skip merge
                        # (already handled by cross-module dedup)
                        continue

                    # Bug #42: Require high parameter overlap (0.8) and ensure
                    # the parameter sets are not just sharing one generic param
                    # among many unique security-relevant ones.
                    if candidate_params or keeper_params:
                        overlap_params = candidate_params & keeper_params
                        union_params = candidate_params | keeper_params
                        param_overlap = len(overlap_params) / max(len(union_params), 1)
                        # Additional guard: if the keeper has many unique params
                        # that the candidate doesn't have (or vice versa), the
                        # attack surface is different — don't merge.
                        keeper_only = keeper_params - candidate_params
                        candidate_only = candidate_params - keeper_params
                        max_unique_diff = max(len(keeper_only), len(candidate_only))
                        # If one side has 2+ unique params the other lacks,
                        # they represent different attack surfaces.
                        if max_unique_diff >= 2:
                            param_overlap = 0.0
                    else:
                        param_overlap = 1.0

                    if param_overlap >= 0.8:
                        keeper_urls = keeper.get("sample_urls", [keeper_url])
                        if candidate_url not in keeper_urls:
                            keeper_urls.append(candidate_url)
                        # Bug #42: Raise cap from 5 to 15 to preserve breadth
                        keeper["sample_urls"] = keeper_urls[:15]
                        keeper["score"] = max(keeper.get("score", 0), candidate.get("score", 0))
                        keeper["confidence"] = round(
                            max(
                                float(keeper.get("confidence", 0)),
                                float(candidate.get("confidence", 0)),
                            ),
                            2,
                        )
                        _merge_finding_context(keeper, candidate)
                        if len(keeper_urls) > 1:
                            keeper["explanation"] = (
                                f"Pattern observed across {len(keeper_urls)} URL variants. "
                                + keeper.get("explanation", "")
                            )
                        merged_indices.add(i)
                        merged = True
                        break
            if not merged:
                kept.append(candidate)
        deduped.extend(kept)
    return deduped


def _apply_correlation(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply cross-finding correlation to enrich findings with attack chain metadata.

    Note: Correlation is now handled by the intelligence layer after findings
    are produced, to maintain proper layer boundaries.
    """
    return findings


def _ensure_category_fields(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ensure every finding has a ``category`` field for intelligence correlation.

    Detection handlers emit ``indicator`` but not ``category``. The severity
    model and ``ThreatIntelCorrelator`` both read ``category`` to do CVE
    matching and calibration. This pass derives ``category`` from ``indicator``
    when it is missing.
    """
    from src.detection.finding import infer_category_from_indicator

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        cat = finding.get("category")
        if not cat or cat == "unknown":
            indicator = finding.get("indicator", "")
            if indicator:
                finding["category"] = infer_category_from_indicator(indicator)
    return findings


def _deduplicate_explanation(explanation: str) -> str:
    """Bug #43: Deduplicate explanation text that accumulates across merge passes.

    Each merge pass prepends/appends explanation fragments.  After
    cross-module dedup + evidence similarity + URL pattern merge, the
    same fragment can appear multiple times.  This function deduplicates
    at the sentence level while preserving ordering.
    """
    if not explanation:
        return explanation

    # Split into sentences on period+space or period+newline boundaries
    import re
    sentences = re.split(r'(?<=\.)\s+', explanation.strip())
    seen: set[str] = set()
    deduped: list[str] = []
    for sentence in sentences:
        normalized = sentence.strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(sentence.strip())
    return " ".join(deduped)


def merge_findings(
    analysis_results: dict[str, list[dict[str, Any]]],
    ranked_priority_urls: list[dict[str, Any]],
    target_profile: dict[str, int | bool],
    mode: str,
    validation_summary: dict[str, Any] | None = None,
    nuclei_findings: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Merge analysis results from multiple plugins into unified findings.

    Optionally merges Nuclei findings when ``nuclei_findings`` is provided.
    """
    from ._merge_anomaly import merge_anomaly
    from ._merge_behavior import merge_behavior
    from ._merge_csrf import merge_csrf
    from ._merge_idor import merge_idor
    from ._merge_misc import merge_misc_findings
    from ._merge_nuclei import merge_nuclei
    from ._merge_payment import merge_payment
    from ._merge_redirect import merge_redirect
    from ._merge_sensitive_data import merge_sensitive_data
    from ._merge_ssrf import merge_ssrf
    from ._merge_ssti import merge_ssti
    from ._merge_token import merge_token

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    priority_scores = {item["url"]: int(item.get("score", 0)) for item in ranked_priority_urls}
    custom_results = (
        validation_summary.get("results", {}) if isinstance(validation_summary, dict) else {}
    )
    anomaly_keys = {
        resolve_endpoint_key(item) for item in analysis_results.get("anomaly_detector", [])
    }

    merge_sensitive_data(analysis_results, priority_scores, seen, findings)
    merge_payment(analysis_results, priority_scores, seen, findings)
    merge_token(analysis_results, priority_scores, anomaly_keys, seen, findings)
    merge_csrf(analysis_results, priority_scores, seen, findings)
    merge_ssti(analysis_results, priority_scores, seen, findings)
    merge_idor(analysis_results, custom_results, priority_scores, anomaly_keys, seen, findings)
    merge_ssrf(analysis_results, custom_results, priority_scores, anomaly_keys, seen, findings)
    merge_redirect(analysis_results, custom_results, priority_scores, anomaly_keys, seen, findings)
    merge_anomaly(analysis_results, priority_scores, seen, findings)
    merge_behavior(analysis_results, seen, findings)
    findings.extend(merge_misc_findings(analysis_results, priority_scores, seen))

    if nuclei_findings:
        findings = merge_nuclei(findings, nuclei_findings)

    flattened = [item for item in findings if item]
    # Bug #44: Ensure category fields BEFORE dedup so grouping decisions
    # use complete metadata.  Previously, category="" caused findings with
    # different vulnerability types to merge incorrectly because the
    # grouping key (category, endpoint, title) had an empty category.
    flattened = _ensure_category_fields(flattened)
    flattened = _dedup_cross_module(flattened)
    flattened = _dedup_evidence_similarity(flattened)
    flattened = _dedup_fuzzy_url_patterns(flattened)
    flattened = _apply_correlation(flattened)
    # Bug #43: Deduplicate explanation text that accumulated across merge passes
    for item in flattened:
        if "explanation" in item:
            item["explanation"] = _deduplicate_explanation(item["explanation"])
    flattened = enrich_findings_with_model_severity(flattened)
    flattened.sort(key=lambda item: (-item.get("score", 0), item["url"], item["title"]))
    return flattened
