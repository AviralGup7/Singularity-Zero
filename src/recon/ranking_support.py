"""URL ranking support utilities for flow analysis, trust boundary detection, and history feedback.

Provides functions for building flow graphs from URL chains, detecting trust
boundary crossings, computing parameter sensitivity scores, deriving URL signals,
and applying history feedback from previous pipeline runs.
"""

import json
import logging
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, TypedDict
from urllib.parse import urlparse

from src.analysis.helpers import (
    REDIRECT_PARAM_NAMES,
    endpoint_base_key,
    endpoint_signature,
    extract_host_candidate,
    is_auth_flow_endpoint,
    is_suspicious_path_redirect,
    meaningful_query_pairs,
    parameter_weight,
    same_host_family,
)

logger = logging.getLogger(__name__)


# Flow graph construction limits
# Maximum number of stages in an auth flow chain for ranking
MAX_FLOW_CHAIN_SLICE = 6
# Maximum number of top flows to return in build_flow_graph output
MAX_FLOWS_RETURNED = 20


class HistoryFeedback(TypedDict):
    hosts: set[str]
    endpoint_keys: set[str]
    endpoint_bases: set[str]
    parameter_names: set[str]


class FlowInfo(TypedDict, total=False):
    flow_host: str
    flow_label: str
    flow_stage: int
    flow_position: int
    flow_chain_size: int


class TrustBoundaryResult(TypedDict):
    level: str
    score: int
    signals: list[str]


class SelectResult(TypedDict):
    selected_count: int
    dynamic_limit: int
    top_flow_groups: list[str]


def _coerce_previous_run_path(previous_run: Any) -> Path | None:
    if previous_run is None:
        return None
    if isinstance(previous_run, Path):
        return previous_run
    if isinstance(previous_run, str):
        normalized = previous_run.strip()
        if not normalized:
            return None
        return Path(normalized)
    try:
        return Path(previous_run)
    except (TypeError, ValueError):
        return None


def _coerce_feedback_set(value: Any) -> set[str]:
    if isinstance(value, set):
        return {str(item) for item in value if str(item).strip()}
    if isinstance(value, (list, tuple, frozenset)):
        return {str(item) for item in value if str(item).strip()}
    if isinstance(value, str):
        text = value.strip()
        return {text} if text else set()
    return set()


def load_history_feedback(previous_run: Path | str | None) -> HistoryFeedback:
    """Load history feedback from a previous pipeline run's findings.

    Args:
        previous_run: Path to previous run output directory.

    Returns:
        Dict with hosts, endpoint_keys, endpoint_bases, and parameter_names sets.
    """
    feedback: HistoryFeedback = {
        "hosts": set(),
        "endpoint_keys": set(),
        "endpoint_bases": set(),
        "parameter_names": set(),
    }
    previous_run_path = _coerce_previous_run_path(previous_run)
    if previous_run_path is None:
        return feedback
    findings_path = previous_run_path / "findings.json"
    if not findings_path.exists():
        return feedback
    try:
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("Failed to load history feedback: %s", exc)
        return feedback

    for item in findings:
        if not isinstance(item, dict):
            continue
        decision = str(item.get("decision", "")).upper()
        severity = str(item.get("severity", "")).lower()
        if decision == "DROP" or severity == "low":
            continue
        url = str(item.get("url") or item.get("evidence", {}).get("url") or "").strip()
        if not url:
            continue
        feedback["hosts"].add(urlparse(url).netloc.lower())
        feedback["endpoint_keys"].add(endpoint_signature(url, include_host=True))
        feedback["endpoint_bases"].add(endpoint_base_key(url, include_host=True))
        for name, _ in meaningful_query_pairs(url):
            feedback["parameter_names"].add(name)
    return feedback


def stage_for_url(url: str) -> int | None:
    lowered = url.lower()
    if "/access" in lowered:
        return 0
    if "/auth" in lowered or "/login" in lowered or "/signin" in lowered:
        return 1
    if "/oauth" in lowered or any(
        name in {"state", "profile", "return_to"} for name, _ in meaningful_query_pairs(url)
    ):
        return 2
    if any(name in REDIRECT_PARAM_NAMES for name, _ in meaningful_query_pairs(url)):
        return 3
    if is_auth_flow_endpoint(url):
        return 4
    if "/api/" in lowered or "/graphql" in lowered:
        return 5
    return None


def build_flow_graph(urls: list[str]) -> dict[str, object]:
    per_host: dict[str, list[tuple[int, str]]] = {}
    per_url: dict[str, dict[str, object]] = {}
    for raw_url in urls:
        stage = stage_for_url(raw_url)
        host = urlparse(raw_url).netloc.lower()
        if not host or stage is None:
            continue
        per_host.setdefault(host, []).append((stage, raw_url))

    flows: list[dict[str, Any]] = []
    for host, items in per_host.items():
        ordered = sorted(items, key=lambda item: (item[0], item[1]))
        chain: list[str] = []
        stage_positions: dict[int, int] = {}
        seen_stages: set[int] = set()
        for stage, url in ordered:
            if stage in seen_stages:
                continue
            seen_stages.add(stage)
            stage_positions[stage] = len(chain)
            chain.append(url)
        if len(chain) < 2:
            continue
        label = (
            "access_auth_oauth_api_chain"
            if any(stage in stage_positions for stage in (0, 1, 2, 5))
            else "auth_redirect_chain"
        )
        flows.append(
            {"host": host, "label": label, "chain": chain[:MAX_FLOW_CHAIN_SLICE], "stage_count": len(chain[:MAX_FLOW_CHAIN_SLICE])}
        )
        for stage, url in ordered:
            per_url[url] = {
                "flow_host": host,
                "flow_label": label,
                "flow_stage": stage,
                "flow_position": stage_positions.get(stage, 0),
                "flow_chain_size": len(chain[:MAX_FLOW_CHAIN_SLICE]),
            }
    flows.sort(key=lambda item: (-item["stage_count"], item["host"]))
    return {"flows": flows[:MAX_FLOWS_RETURNED], "per_url": per_url}


def detect_trust_boundary(url: str) -> TrustBoundaryResult:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    result: TrustBoundaryResult = {"level": "same-host", "score": 0, "signals": []}
    for name, value in meaningful_query_pairs(url):
        if name not in REDIRECT_PARAM_NAMES and name not in {"state", "profile", "uri"}:
            continue
        target_host = extract_host_candidate(value)
        if target_host:
            if same_host_family(host, target_host):
                result["signals"].append(f"same_host_target:{name}")
                result["score"] = max(int(result["score"]), 2)
                continue
            result["level"] = "cross-host"
            result["signals"].append(f"cross_host_target:{name}")
            result["score"] = max(int(result["score"]), 10)
            continue
        if is_suspicious_path_redirect(value):
            if result["level"] != "cross-host":
                result["level"] = "restricted-path"
            result["signals"].append(f"restricted_path_target:{name}")
            result["score"] = max(int(result["score"]), 6)
    return result


def parameter_sensitivity_score(url: str) -> int:
    score = 0
    for name, _ in meaningful_query_pairs(url):
        score += max(parameter_weight(name) - 1, 0)
        if name in {"token", "session", "jwt", "state"}:
            score += 3
        elif name in {
            "callback",
            "redirect",
            "return",
            "return_to",
            "url",
            "uri",
            "dest",
            "destination",
        }:
            score += 3
        elif name in {"file", "path", "filename", "attachment"}:
            score += 2
        elif name == "id" or name.endswith("_id"):
            score += 2
    return score


def derive_url_signals(url: str) -> set[str]:
    lowered = url.lower()
    parameter_names = {name for name, _ in meaningful_query_pairs(url)}
    signals: set[str] = set()
    if is_auth_flow_endpoint(url):
        signals.add("auth")
    if any(name in REDIRECT_PARAM_NAMES for name in parameter_names):
        signals.add("redirect")
    if any(name in {"callback", "url", "uri", "dest", "destination"} for name in parameter_names):
        signals.add("callback")
    if any(name in {"token", "state", "session", "jwt"} for name in parameter_names):
        signals.add("token")
    if any(name == "id" or name.endswith("_id") for name in parameter_names):
        signals.add("idor")
    if any(name in {"file", "path", "filename", "attachment"} for name in parameter_names) or any(
        token in lowered for token in ("upload", "download", "file")
    ):
        signals.add("file")
    if "/api/" in lowered or "/graphql" in lowered:
        signals.add("api")
    return signals


def cluster_key(url: str) -> str:
    params = sorted({name for name, _ in meaningful_query_pairs(url)})
    family = []
    for name in params:
        if name == "id" or name.endswith("_id"):
            family.append("object")
        elif name in {"token", "state", "session", "jwt"}:
            family.append("token")
        elif name in REDIRECT_PARAM_NAMES or name in {"uri", "profile"}:
            family.append("redirect")
        elif name in {"file", "path", "filename", "attachment"}:
            family.append("file")
        else:
            family.append(name)
    parsed = urlparse(url)
    return f"{parsed.netloc.lower()}|{parsed.path.lower()}|{'&'.join(sorted(set(family)))}"


def history_feedback_score(url: str, feedback: HistoryFeedback | None) -> int:
    if not feedback:
        return 0
    score = 0
    host = urlparse(url).netloc.lower()
    hosts = _coerce_feedback_set(feedback.get("hosts", set()))
    endpoint_keys = _coerce_feedback_set(feedback.get("endpoint_keys", set()))
    endpoint_bases = _coerce_feedback_set(feedback.get("endpoint_bases", set()))
    parameter_names = _coerce_feedback_set(feedback.get("parameter_names", set()))

    if host in hosts:
        score += 4
    if endpoint_signature(url, include_host=True) in endpoint_keys:
        score += 6
    elif endpoint_base_key(url, include_host=True) in endpoint_bases:
        score += 3
    matched_params = parameter_names & {name for name, _ in meaningful_query_pairs(url)}
    score += min(len(matched_params), 3) * 2
    return score


def normalize_ranked_scores(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not items:
        return items
    raw_scores = [float(item.get("score", 0)) for item in items]
    low = min(raw_scores)
    high = max(raw_scores)
    spread = high - low
    average = mean(raw_scores)
    deviation = pstdev(raw_scores) if len(raw_scores) > 1 else 0.0
    normalized = []
    for item in items:
        raw = float(item.get("score", 0))
        percentile = 100.0 if spread <= 0 else ((raw - low) / spread) * 100.0
        z_score = 0.0 if deviation <= 0 else (raw - average) / deviation
        normalized.append(
            {
                **item,
                "normalized_score": round(percentile, 2),
                "score_z": round(z_score, 3),
            }
        )
    return normalized


def select_deep_analysis_targets(
    ranked_items: list[dict[str, Any]], analysis_config: dict[str, Any], mode: str
) -> tuple[list[dict[str, Any]], SelectResult]:
    if not ranked_items:
        return [], {"selected_count": 0, "dynamic_limit": 0, "top_flow_groups": []}

    configured = max(1, int(analysis_config.get("deep_analysis_top_n", 15)))
    adaptive_floor = max(configured, min(len(ranked_items), max(12, int(len(ranked_items) * 0.2))))
    top_scores = [
        float(item.get("score", 0)) for item in ranked_items[: min(len(ranked_items), 12)]
    ]
    dynamic_limit = adaptive_floor
    if len(top_scores) >= 4:
        tail_mean = mean(top_scores[3:])
        head_mean = mean(top_scores[:3])
        if head_mean >= tail_mean + 8:
            dynamic_limit = max(configured, min(adaptive_floor, 12))
        elif mode.lower() == "aggressive":
            dynamic_limit = max(dynamic_limit, 24)
    else:
        dynamic_limit = adaptive_floor

    if mode.lower() == "safe":
        dynamic_limit = min(dynamic_limit, 10)

    top_groups: dict[str, list[dict[str, Any]]] = {}
    for item in ranked_items:
        key = str(
            item.get("flow_group")
            or item.get("cluster_key")
            or item.get("canonical_key")
            or item.get("url")
        )
        top_groups.setdefault(key, []).append(item)
    ordered_groups = sorted(
        top_groups.items(),
        key=lambda entry: (
            entry[1][0].get("decision_override") != "HIGH",
            -float(entry[1][0].get("score", 0)),
            -int(entry[1][0].get("flow_chain_size", 0)),
        ),
    )

    selected: list[dict[str, Any]] = []
    selected_groups: list[str] = []
    for group_key, group_items in ordered_groups[:3]:
        selected_groups.append(group_key)
        selected.extend(group_items[:3])
        if len(selected) >= dynamic_limit:
            break
    if len(selected) < min(dynamic_limit, 5):
        seen_urls = {str(item.get("url")) for item in selected}
        for item in ranked_items:
            url = str(item.get("url", ""))
            if url in seen_urls:
                continue
            selected.append(item)
            seen_urls.add(url)
            if len(selected) >= dynamic_limit:
                break
    return selected[:dynamic_limit], {
        "selected_count": min(len(selected), dynamic_limit),
        "dynamic_limit": dynamic_limit,
        "top_flow_groups": selected_groups,
    }
