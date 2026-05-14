"""URL scoring and ranking engine for recon pipeline.

Provides context-aware URL scoring based on keyword weights, endpoint types,
target profiles, mode bonuses, flow analysis, and trust boundary detection.
Includes both standard and precomputed variants for performance optimization.
"""

from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    has_meaningful_parameters,
    is_auth_flow_endpoint,
    is_low_value_endpoint,
    is_noise_url,
    meaningful_query_pairs,
    parameter_weight,
)
from src.recon.ranking_support import (
    HistoryFeedback,
    build_flow_graph,
    cluster_key,
    derive_url_signals,
    detect_trust_boundary,
    history_feedback_score,
    normalize_ranked_scores,
)


def infer_target_profile(urls: Iterable[str]) -> dict[str, int | bool]:
    url_list = list(urls)
    total = max(1, len(url_list))
    api_hits = sum(
        1
        for url in url_list
        if any(token in url.lower() for token in ["/api/", "graphql", "swagger"])
    )
    auth_hits = sum(
        1
        for url in url_list
        if any(token in url.lower() for token in ["/auth", "/login", "/oauth", "token", "session"])
    )
    param_hits = sum(1 for url in url_list if query_parameter_names(url))
    upload_hits = sum(
        1
        for url in url_list
        if any(token in url.lower() for token in ["upload", "file", "attachment", "download"])
    )
    return {
        "api_heavy": api_hits / total >= 0.2,
        "auth_heavy": auth_hits / total >= 0.12,
        "parameter_heavy": param_hits / total >= 0.25,
        "file_heavy": upload_hits / total >= 0.08,
        "total_urls": len(url_list),
        "api_ratio_percent": round((api_hits / total) * 100),
        "auth_ratio_percent": round((auth_hits / total) * 100),
        "parameter_ratio_percent": round((param_hits / total) * 100),
    }


def query_parameter_names(url: str) -> list[str]:
    return [key for key, _ in meaningful_query_pairs(url)]


def resolve_priority_limit(
    filters: Mapping[str, Any], mode: str, profile: dict[str, int | bool] | None = None
) -> int:
    def _coerce_limit(value: Any, default: int = 100) -> int:
        if isinstance(value, Mapping):
            value = value.get("default")
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    configured = filters.get("priority_limit", 100)
    if isinstance(configured, Mapping):
        selected: Any = configured.get(mode)
        if selected is None and profile:
            total_urls = int(profile.get("total_urls", 0) or 0)
            if bool(profile.get("api_heavy", False)):
                selected = configured.get("api_heavy")
            elif total_urls > 0 and total_urls <= 80:
                selected = configured.get("small_target")
        if selected is None:
            selected = configured.get("default", 100)
        if selected is None:
            return 100
        return _coerce_limit(selected)
    return _coerce_limit(configured)


def score_mode_bonus(url: str, scoring: dict[str, Any], mode: str) -> int:
    mode_config = scoring.get("modes", {}).get(mode.lower(), {})
    if not mode_config:
        return 0

    param_bonus = int(mode_config.get("param_bonus", 0))
    parameter_keywords = [item.lower() for item in mode_config.get("parameter_keywords", [])]
    path_keywords = [item.lower() for item in mode_config.get("path_keywords", [])]
    parameter_names = query_parameter_names(url)
    lowered = url.lower()
    score = 0

    if param_bonus and parameter_keywords:
        if any(keyword in name for name in parameter_names for keyword in parameter_keywords):
            score += param_bonus
    if param_bonus and path_keywords:
        if any(keyword in lowered for keyword in path_keywords):
            score += param_bonus
    return score


def score_mode_bonus_precomputed(
    lowered: str, parameter_names: list[str], scoring: dict[str, Any], mode: str
) -> int:
    mode_config = scoring.get("modes", {}).get(mode.lower(), {})
    if not mode_config:
        return 0

    param_bonus = int(mode_config.get("param_bonus", 0))
    parameter_keywords = [item.lower() for item in mode_config.get("parameter_keywords", [])]
    path_keywords = [item.lower() for item in mode_config.get("path_keywords", [])]
    score = 0

    if param_bonus and parameter_keywords:
        if any(keyword in name for name in parameter_names for keyword in parameter_keywords):
            score += param_bonus
    if param_bonus and path_keywords:
        if any(keyword in lowered for keyword in path_keywords):
            score += param_bonus
    return score


def score_context_bonus(url: str, scoring: dict[str, Any], profile: dict[str, int | bool]) -> int:
    lowered = url.lower()
    score = 0
    for label, enabled in profile.items():
        if not isinstance(enabled, bool) or not enabled:
            continue
        context = scoring.get("contexts", {}).get(label, {})
        bonus = int(context.get("bonus", 0))
        keywords = [str(item).lower() for item in context.get("keywords", [])]
        if bonus and keywords and any(keyword in lowered for keyword in keywords):
            score += bonus
    return score


def score_context_bonus_precomputed(
    lowered: str, scoring: dict[str, Any], profile: dict[str, int | bool]
) -> int:
    score = 0
    for label, enabled in profile.items():
        if not isinstance(enabled, bool) or not enabled:
            continue
        context = scoring.get("contexts", {}).get(label, {})
        bonus = int(context.get("bonus", 0))
        keywords = [str(item).lower() for item in context.get("keywords", [])]
        if bonus and keywords and any(keyword in lowered for keyword in keywords):
            score += bonus
    return score


def score_url(
    url: str,
    filters: dict[str, Any],
    scoring: dict[str, Any],
    mode: str,
    profile: dict[str, int | bool] | None = None,
) -> int:
    score = 0
    lowered = url.lower()
    keyword_weights = {
        str(keyword).lower(): int(weight) for keyword, weight in scoring.get("weights", {}).items()
    }
    for keyword, weight in keyword_weights.items():
        if keyword == "param":
            continue
        if keyword in lowered:
            score += weight

    parameter_names = query_parameter_names(url)
    if parameter_names:
        score += int(keyword_weights.get("param", 0))
        score += sum(parameter_weight(name) - 1 for name in parameter_names)

    score += score_mode_bonus(url, scoring, mode)
    if profile:
        score += score_context_bonus(url, scoring, profile)
    custom_keyword_bonus = int(scoring.get("custom_keyword_bonus", 2))
    for custom_keyword in filters.get("priority_keywords", []):
        if custom_keyword.lower() in lowered:
            score += custom_keyword_bonus
    endpoint_type = classify_endpoint(url)
    if endpoint_type == "API":
        score += 2
    if endpoint_type == "REDIRECT":
        score += 2
    if is_auth_flow_endpoint(url):
        score += 3
    if is_auth_flow_endpoint(url) and any(
        name in {"next", "redirect", "return", "return_to", "state", "url"}
        for name in parameter_names
    ):
        score += 4
    if is_low_value_endpoint(url):
        score -= 4
    if not has_meaningful_parameters(url):
        score -= 6
    return score


def score_url_precomputed(
    *,
    lowered: str,
    parameter_names: list[str],
    endpoint_type: str,
    is_auth_flow: bool,
    has_meaningful_params: bool,
    filters: dict[str, Any],
    mode: str,
    profile: dict[str, int | bool] | None,
    keyword_weights: dict[str, int],
    custom_priority_keywords: list[str],
    custom_keyword_bonus: int,
    scoring: dict[str, Any],
) -> int:
    score = 0
    for keyword, weight in keyword_weights.items():
        if keyword == "param":
            continue
        if keyword in lowered:
            score += weight

    if parameter_names:
        score += int(keyword_weights.get("param", 0))
        score += sum(parameter_weight(name) - 1 for name in parameter_names)

    score += score_mode_bonus_precomputed(lowered, parameter_names, scoring, mode)
    if profile:
        score += score_context_bonus_precomputed(lowered, scoring, profile)
    for custom_keyword in custom_priority_keywords:
        if custom_keyword in lowered:
            score += custom_keyword_bonus
    if endpoint_type == "API":
        score += 2
    if endpoint_type == "REDIRECT":
        score += 2
    if is_auth_flow:
        score += 3
    if is_auth_flow and any(
        name in {"next", "redirect", "return", "return_to", "state", "url"}
        for name in parameter_names
    ):
        score += 4
    if is_low_value_endpoint(lowered):
        score -= 4
    if not has_meaningful_params:
        score -= 6
    return score


def flow_score(url: str) -> int:
    lowered = url.lower()
    parameter_names = query_parameter_names(url)
    score = 0
    if "/access" in lowered:
        score += 2
    if any(token in lowered for token in ["/auth", "/login", "/signin"]):
        score += 4
    if "/oauth" in lowered:
        score += 5
    if any(
        name in {"next", "redirect", "return", "return_to", "state", "url", "callback"}
        for name in parameter_names
    ):
        score += 5
    if is_auth_flow_endpoint(url):
        score += 3
    if len(parameter_names) >= 2 and any(
        name in {"token", "state", "code"} for name in parameter_names
    ):
        score += 2
    return score


def flow_score_precomputed(lowered: str, parameter_names: list[str], is_auth_flow: bool) -> int:
    score = 0
    if "/access" in lowered:
        score += 2
    if any(token in lowered for token in ["/auth", "/login", "/signin"]):
        score += 4
    if "/oauth" in lowered:
        score += 5
    if any(
        name in {"next", "redirect", "return", "return_to", "state", "url", "callback"}
        for name in parameter_names
    ):
        score += 5
    if is_auth_flow:
        score += 3
    if len(parameter_names) >= 2 and any(
        name in {"token", "state", "code"} for name in parameter_names
    ):
        score += 2
    return score


def rank_urls(
    urls: Iterable[str],
    filters: dict[str, Any],
    scoring: dict[str, Any],
    mode: str,
    profile: dict[str, int | bool] | None = None,
    history_feedback: HistoryFeedback | None = None,
) -> list[dict[str, Any]]:
    """Rank URLs by composite security-relevant score.

    Scoring Algorithm Overview:
    ───────────────────────────────────
    1. Preprocessing:
       - Infer target profile from URL distribution if not provided
         (api_heavy, auth_heavy, parameter_heavy, file_heavy).
       - Build flow graph to detect auth flows and endpoint relationships.
       - Set up keyword weights, custom priority keywords, ignored extensions.
    2. Per-URL Scoring (score_url_precomputed):
       - Keyword match scoring from scoring["weights"]
       - Parameter presence bonus + parameter_weight per parameter name
       - Mode bonus (param_bonus for path/param keywords in focused mode)
       - Context bonus for api_heavy, auth_heavy, etc.
       - Custom priority keyword matches
       - Endpoint type bonuses (API, REDIRECT +2 each)
       - Auth flow endpoint +3, auth flow with sensitive params +4
       - Low-value endpoint penalty -4
       - No meaningful parameters penalty -6
    3. Flow Score (flow_score_precomputed):
       - /access +2, /auth or /login +4, /oauth +5
       - Sensitive redirect params (next, redirect, state, callback) +5
       - Auth flow endpoint +3
       - Multiple sensitive parameters +2
    4. Composite Score = base_score + flow + parameter_sensitivity
       + trust_boundary_score + history_bonus + correlation_boost.
    5. Signal Correlation Boost: +6 if signal_count >= 2, +10 if >= 3,
       +10 for cross-host trust boundary, +5 for restricted-path.
    6. Filtering & Selection:
       - Skip URLs with ignored extensions, noise URLs, duplicate canonical keys.
       - Compute composite_score, skip if <= 0.
       - Normalize scores to 0-100 range.
       - Strict tier: requires params OR signal_count>=2 OR cross-host OR score>=22.
       - Relaxed tier: if strict < 60% of limit, add highest-scoring URLs
         with score >= 14 to fill to minimum_keep (60% of limit).
       - Sort by: decision_override (HIGH first), signal_count desc, score desc,
         normalized_score desc, flow_score desc, URL ascending.
       - Return top `limit` URLs.

    Args:
        urls: Iterable of URL strings to rank.
        filters: Dict with ignore_extensions, priority_keywords, priority_limit.
        scoring: Dict with weights, modes, contexts, custom_keyword_bonus.
        mode: Scan mode (e.g., 'full', 'idor', 'ssrf') for mode bonuses.
        profile: Optional target profile dict for context scoring.
        history_feedback: Optional HistoryFeedback for past-run bonuses.

    Returns:
        List of dicts with url, score components, signals, trust_boundary,
        normalized_score, and flow metadata. Sorted by priority.
    """
    url_list = list(urls)
    active_profile = profile or infer_target_profile(url_list)
    ignored = [item.lower() for item in filters.get("ignore_extensions", [])]
    ignored_suffixes = tuple(ignored)
    keyword_weights = {
        str(keyword).lower(): int(weight) for keyword, weight in scoring.get("weights", {}).items()
    }
    custom_priority_keywords = [str(item).lower() for item in filters.get("priority_keywords", [])]
    custom_keyword_bonus = int(scoring.get("custom_keyword_bonus", 2))
    flow_graph = build_flow_graph(url_list)
    flow_map: dict[str, dict[str, object]] = flow_graph.get("per_url", {})
    ranked = []
    seen_canonical: set[str] = set()
    for url in url_list:
        lowered = url.lower()
        path = urlparse(url).path.lower()
        if ignored_suffixes and path.endswith(ignored_suffixes):
            continue
        if is_noise_url(url):
            continue
        canonical_key = endpoint_signature(url, include_host=True)
        if canonical_key in seen_canonical:
            continue
        seen_canonical.add(canonical_key)

        parameter_names = query_parameter_names(url)
        has_meaningful_params = bool(parameter_names)
        endpoint_type = classify_endpoint(url)
        is_auth_flow = is_auth_flow_endpoint(url)
        signals = derive_url_signals(url)
        if not parameter_names and not signals:
            continue

        score = score_url_precomputed(
            lowered=lowered,
            parameter_names=parameter_names,
            endpoint_type=endpoint_type,
            is_auth_flow=is_auth_flow,
            has_meaningful_params=has_meaningful_params,
            filters=filters,
            mode=mode,
            profile=active_profile,
            keyword_weights=keyword_weights,
            custom_priority_keywords=custom_priority_keywords,
            custom_keyword_bonus=custom_keyword_bonus,
            scoring=scoring,
        )
        flow = flow_score_precomputed(lowered, parameter_names, is_auth_flow)
        parameter_sensitivity = sum(parameter_weight(name) for name in parameter_names)
        trust_boundary = detect_trust_boundary(url)
        history_bonus = history_feedback_score(url, history_feedback)
        flow_meta = flow_map.get(url, {})
        if flow_meta:
            signals.add("flow")
        signals.update(trust_boundary.get("signals", []))
        signal_count = len(signals)
        correlation_boost = 0
        if signal_count >= 2:
            correlation_boost += 6
        if signal_count >= 3:
            correlation_boost += 10
        if trust_boundary.get("level") == "cross-host":
            correlation_boost += 10
        elif trust_boundary.get("level") == "restricted-path":
            correlation_boost += 5

        composite_score = (
            score
            + flow
            + parameter_sensitivity
            + int(trust_boundary.get("score", 0))
            + history_bonus
            + correlation_boost
        )
        if composite_score <= 0:
            continue
        decision_override = "HIGH" if trust_boundary.get("level") == "cross-host" else ""
        ranked.append(
            {
                "url": url,
                "score": composite_score,
                "base_score": score,
                "flow_score": flow,
                "has_parameters": has_meaningful_params,
                "parameter_names": parameter_names,
                "parameter_sensitivity": parameter_sensitivity,
                "endpoint_type": endpoint_type,
                "canonical_key": canonical_key,
                "cluster_key": cluster_key(url),
                "signals": sorted(signals),
                "signal_count": signal_count,
                "cooccurrence_key": "+".join(sorted(signals)),
                "trust_boundary": trust_boundary.get("level", "same-host"),
                "trust_boundary_score": int(trust_boundary.get("score", 0)),
                "history_bonus": history_bonus,
                "decision_override": decision_override,
                "flow_label": flow_meta.get("flow_label", ""),
                "flow_stage": flow_meta.get("flow_stage"),
                "flow_position": int(flow_meta.get("flow_position", 0)),
                "flow_chain_size": int(flow_meta.get("flow_chain_size", 0)),
                "flow_group": str(flow_meta.get("flow_label", ""))
                + "|"
                + str(flow_meta.get("flow_host", "")),
            }
        )

    ranked = normalize_ranked_scores(ranked)
    limit = resolve_priority_limit(filters, mode, active_profile)

    strict_ranked = [
        item
        for item in ranked
        if item["has_parameters"]
        or item.get("signal_count", 0) >= 2
        or item.get("trust_boundary") == "cross-host"
        or float(item.get("score", 0)) >= 22
    ]

    minimum_keep = max(12, int(limit * 0.6))
    if len(strict_ranked) < minimum_keep:
        selected_urls = {str(item.get("url", "")) for item in strict_ranked}
        relaxed_candidates = [
            item
            for item in ranked
            if str(item.get("url", "")) not in selected_urls and float(item.get("score", 0)) >= 14
        ]
        strict_ranked.extend(relaxed_candidates[: max(0, minimum_keep - len(strict_ranked))])

    strict_ranked.sort(
        key=lambda item: (
            item.get("decision_override") != "HIGH",
            -item.get("signal_count", 0),
            -item["score"],
            -item.get("normalized_score", 0),
            -item.get("flow_score", 0),
            item["url"],
        )
    )
    return strict_ranked[:limit]


def prioritize_urls(
    urls: Iterable[str], filters: dict[str, Any], scoring: dict[str, Any], mode: str
) -> list[str]:
    return [item["url"] for item in rank_urls(urls, filters, scoring, mode)]


SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
}

# Aggregate risk score thresholds for labeling
_AGGREGATE_RISK_CRITICAL_THRESHOLD = 50
_AGGREGATE_RISK_HIGH_THRESHOLD = 30
_AGGREGATE_RISK_MEDIUM_THRESHOLD = 15


def compute_aggregate_risk_score(
    findings: list[dict[str, Any]], run_summary: dict[str, Any]
) -> dict[str, Any]:
    """Compute aggregate risk score from findings, severity-weighted.

    Args:
        findings: List of finding dicts with at least a 'severity' key.
        run_summary: Run summary dict with counts and metadata.

    Returns:
        Dict with aggregate_score, severity_breakdown, max_severity,
        finding_count, score_label, and per-category scores.
    """
    severity_counts: dict[str, int] = {}
    category_scores: dict[str, float] = {}
    total_weighted = 0.0
    max_severity = "info"
    severity_order = ["critical", "high", "medium", "low", "info"]

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        sev = str(finding.get("severity", "info")).strip().lower() or "info"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        weight = SEVERITY_WEIGHTS.get(sev, 0)
        total_weighted += weight

        category = str(finding.get("category", "uncategorized")).strip().lower() or "uncategorized"
        category_scores[category] = category_scores.get(category, 0) + weight

        if severity_order.index(sev) < severity_order.index(max_severity):
            max_severity = sev

    finding_count = len(findings)
    avg_score = round(total_weighted / finding_count, 2) if finding_count > 0 else 0.0

    if total_weighted >= _AGGREGATE_RISK_CRITICAL_THRESHOLD:
        score_label = "critical"
    elif total_weighted >= _AGGREGATE_RISK_HIGH_THRESHOLD:
        score_label = "high"
    elif total_weighted >= _AGGREGATE_RISK_MEDIUM_THRESHOLD:
        score_label = "medium"
    elif total_weighted > 0:
        score_label = "low"
    else:
        score_label = "info"

    return {
        "aggregate_score": round(total_weighted, 2),
        "average_score": avg_score,
        "severity_breakdown": severity_counts,
        "max_severity": max_severity,
        "finding_count": finding_count,
        "score_label": score_label,
        "category_scores": dict(sorted(category_scores.items(), key=lambda x: -x[1])),
        "run_id": run_summary.get("run_id", ""),
        "generated_at": run_summary.get("generated_at_utc", ""),
    }


def compute_historical_score(
    endpoint: str, current_score: float, past_runs: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compute historical score evolution for an endpoint across runs.

    Args:
        endpoint: The URL/endpoint to track.
        current_score: Current run score for the endpoint.
        past_runs: List of past run data dicts, each containing
                   endpoint scores and findings.

    Returns:
        Dict with trend, score_history, finding_frequency,
        first_seen, last_seen, trend_direction, and risk_delta.
    """
    score_history: list[dict[str, Any]] = []
    finding_frequency = 0
    first_seen = ""
    last_seen = ""
    total_runs = len(past_runs) + 1

    for i, run in enumerate(past_runs):
        if not isinstance(run, dict):
            continue
        run_score = run.get("score", 0.0)
        run_findings = run.get("findings", [])
        run_timestamp = run.get("timestamp", run.get("generated_at", ""))
        score_history.append(
            {
                "run_index": i,
                "score": run_score,
                "finding_count": len(run_findings) if isinstance(run_findings, list) else 0,
                "timestamp": run_timestamp,
            }
        )
        if run_findings:
            finding_frequency += 1

    score_history.append(
        {
            "run_index": len(past_runs),
            "score": current_score,
            "finding_count": 0,
            "timestamp": "",
        }
    )

    if past_runs:
        first_seen = past_runs[0].get("timestamp", past_runs[0].get("generated_at", ""))
        last_seen = past_runs[-1].get("timestamp", past_runs[-1].get("generated_at", ""))

    scores_only = [entry["score"] for entry in score_history]
    if len(scores_only) >= 2:
        recent_avg = sum(scores_only[-3:]) / min(3, len(scores_only))
        older_avg = (
            sum(scores_only[:-3]) / max(1, len(scores_only) - 3)
            if len(scores_only) > 3
            else scores_only[0]
        )
        risk_delta = round(current_score - older_avg, 2)
        if recent_avg > older_avg * 1.1:
            trend_direction = "increasing"
        elif recent_avg < older_avg * 0.9:
            trend_direction = "decreasing"
        else:
            trend_direction = "stable"
    else:
        risk_delta = 0.0
        trend_direction = "insufficient_data"

    finding_freq_ratio = round(finding_frequency / max(1, len(past_runs)), 2)

    return {
        "endpoint": endpoint,
        "current_score": current_score,
        "trend_direction": trend_direction,
        "risk_delta": risk_delta,
        "score_history": score_history,
        "finding_frequency": finding_freq_ratio,
        "total_runs_with_findings": finding_frequency,
        "total_runs_tracked": total_runs,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }
