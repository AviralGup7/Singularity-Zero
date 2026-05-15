"""Intelligence insights builder for attack surface, trends, and next steps.

Analyzes findings and analysis results to build actionable intelligence
summaries including attack surface metrics, trend analysis, technology
fingerprints, manual verification queues, and high-confidence shortlists.
"""

import json
from pathlib import Path
from typing import Any

from src.analysis.automation.manual_queue import (
    MANUAL_QUEUE_CATEGORIES,
    attach_queue_replay_links,
    build_automation_tasks,
    build_review_brief,
    derive_endpoint_type,
)
from src.analysis.behavior.technology import build_technology_summary
from src.analysis.intelligence.findings_dedup import finding_key
from src.core.logging.trace_logging import get_pipeline_logger
from src.execution.exploiters.exploit_automation import build_chain_simulation, build_proof_bundle

__all__ = [
    "build_attack_surface",
    "build_trend",
    "build_next_steps",
    "build_feedback_targets",
    "build_manual_verification_queue",
    "build_high_confidence_shortlist",
    "build_cross_finding_correlation",
    "build_technology_summary",
    "attach_queue_replay_links",
]

logger = get_pipeline_logger(__name__)


def build_attack_surface(
    findings: list[dict[str, Any]], ranked_priority_urls: list[dict[str, Any]]
) -> dict[str, int]:
    counts = {"high_value_endpoints": len(ranked_priority_urls)}
    for finding in findings:
        counts[finding["category"]] = counts.get(finding["category"], 0) + 1
        if finding.get("combined_signal"):
            counts["multi_signal_endpoints"] = counts.get("multi_signal_endpoints", 0) + 1
    return counts


def build_trend(previous_run: Path | None, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare current findings against previous run to identify trends.

    Args:
        previous_run: Path to previous run output directory.
        findings: Current run findings list.

    Returns:
        Dict with new_findings, resolved_findings, stable_findings counts,
        plus severity_trend, category_trend, and confidence_trend metrics.
    """
    current_keys = {finding_key(item) for item in findings}
    if previous_run is None or not (previous_run / "findings.json").exists():
        return {
            "new_findings": len(current_keys),
            "resolved_findings": 0,
            "stable_findings": 0,
            "severity_trend": {},
            "category_trend": {},
            "confidence_trend": {"improved": 0, "degraded": 0, "unchanged": 0},
            "trend_summary": "First run â€” no historical comparison available.",
        }
    try:
        previous_findings = json.loads((previous_run / "findings.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load previous findings for trend analysis: %s", exc)
        previous_findings = []
    previous_keys = {finding_key(item) for item in previous_findings if isinstance(item, dict)}

    # Build lookup maps for detailed trend analysis
    previous_by_key: dict[str, dict[str, Any]] = {}
    for item in previous_findings:
        if isinstance(item, dict):
            previous_by_key[finding_key(item)] = item

    # Severity trend: track how severity changed for stable findings
    severity_trend: dict[str, int] = {"improved": 0, "degraded": 0, "unchanged": 0}
    # Category trend: track new vs resolved categories
    current_categories: dict[str, int] = {}
    previous_categories: dict[str, int] = {}
    # Confidence trend: track confidence changes for stable findings
    confidence_trend = {"improved": 0, "degraded": 0, "unchanged": 0}

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for item in findings:
        cat = item.get("category", "unknown")
        current_categories[cat] = current_categories.get(cat, 0) + 1
        key = finding_key(item)
        if key in previous_by_key:
            prev = previous_by_key[key]
            # Severity comparison
            prev_sev = severity_order.get(str(prev.get("severity", "low")).lower(), 0)
            curr_sev = severity_order.get(str(item.get("severity", "low")).lower(), 0)
            if curr_sev > prev_sev:
                severity_trend["degraded"] += 1
            elif curr_sev < prev_sev:
                severity_trend["improved"] += 1
            else:
                severity_trend["unchanged"] += 1
            # Confidence comparison
            prev_conf = float(prev.get("confidence", 0))
            curr_conf = float(item.get("confidence", 0))
            if curr_conf > prev_conf + 0.05:
                confidence_trend["improved"] += 1
            elif curr_conf < prev_conf - 0.05:
                confidence_trend["degraded"] += 1
            else:
                confidence_trend["unchanged"] += 1

    for item in previous_findings:
        if isinstance(item, dict):
            cat = item.get("category", "unknown")
            previous_categories[cat] = previous_categories.get(cat, 0) + 1

    # Category trend: new categories vs resolved categories
    new_categories = set(current_categories.keys()) - set(previous_categories.keys())
    resolved_categories = set(previous_categories.keys()) - set(current_categories.keys())

    # Build trend summary
    total_stable = len(current_keys & previous_keys)
    if total_stable > 0:
        if severity_trend["degraded"] > severity_trend["improved"]:
            trend_summary = f"Security posture degraded: {severity_trend['degraded']} findings increased severity vs {severity_trend['improved']} improved."
        elif severity_trend["improved"] > severity_trend["degraded"]:
            trend_summary = f"Security posture improved: {severity_trend['improved']} findings decreased severity vs {severity_trend['degraded']} degraded."
        else:
            trend_summary = f"Security posture stable: {severity_trend['unchanged']} findings unchanged, {len(new_categories)} new categories, {len(resolved_categories)} resolved categories."
    else:
        trend_summary = "All findings are new â€” no stable findings for trend comparison."

    return {
        "new_findings": len(current_keys - previous_keys),
        "resolved_findings": len(previous_keys - current_keys),
        "stable_findings": total_stable,
        "severity_trend": severity_trend,
        "category_trend": {
            "new_categories": sorted(new_categories),
            "resolved_categories": sorted(resolved_categories),
            "current_distribution": current_categories,
            "previous_distribution": previous_categories,
        },
        "confidence_trend": confidence_trend,
        "trend_summary": trend_summary,
    }


def build_next_steps(
    findings: list[dict[str, Any]],
    target_profile: dict[str, int | bool],
    parameters: set[str],
    mode: str,
    technology_summary: list[dict[str, Any]] | None = None,
    validation_summary: dict[str, Any] | None = None,
) -> list[str]:
    suggestions: list[str] = []
    categories = {item["category"] for item in findings}
    # Extract validation context for escalation-aware recommendations
    validated_confirmed: set[str] = set()
    validated_unconfirmed: set[str] = set()
    validated_multi_strategy: set[str] = set()
    if validation_summary:
        results = (
            validation_summary.get("results", {}) if isinstance(validation_summary, dict) else {}
        )
        for category, items in results.items():
            if isinstance(items, list):
                for v_item in items:
                    state = str(v_item.get("validation_state", "")).lower()
                    cat = str(v_item.get("category", category)).lower()
                    if state in {"confirmed", "active_ready", "exploitable"}:
                        validated_confirmed.add(cat)
                    elif state in {"unconfirmed", "inactive", "false_positive"}:
                        validated_unconfirmed.add(cat)
                    if state == "multi_strategy_confirmed":
                        validated_multi_strategy.add(cat)
    if ("idor" in categories or "access_control" in categories) and mode.lower() != "idor":
        if "idor" in validated_multi_strategy:
            suggestions.append(
                "IDOR was multi-strategy confirmed â€” prioritize immediate remediation and test all related object reference endpoints for the same access control gap."
            )
        elif "idor" in validated_confirmed:
            suggestions.append(
                "IDOR was confirmed in validation â€” escalate to cross-tenant and cross-role access testing with additional identity contexts."
            )
        else:
            suggestions.append(
                "Switch to IDOR-focused mode for the next run to bias scoring and scanning toward object references."
            )
    if "ssrf" in categories and mode.lower() != "ssrf":
        if "ssrf" in validated_confirmed:
            suggestions.append(
                "SSRF validation confirmed active callbacks â€” escalate to blind SSRF with OOB infrastructure and DNS/HTTP callback chaining."
            )
        else:
            suggestions.append(
                "Run an SSRF-focused pass and validate callback-style parameters with controlled out-of-band infrastructure."
            )
    if "open_redirect" in categories:
        suggestions.append(
            "Validate high-confidence redirect flows with absolute, same-host, and path-only targets to confirm trust-boundary handling."
        )
    if "oauth_flow" in categories:
        suggestions.append(
            "Treat OAuth and signin return flows as first-class logic targets and review nested state, return_to, and redirect chains."
        )
    if "behavioral_deviation" in categories:
        suggestions.append(
            "Replay confirmed single-parameter variants from the manual queue and compare the stored before/after snapshots to validate reproducible logic changes."
        )
    if "access_control" in categories:
        if "access_control" in validated_confirmed:
            suggestions.append(
                "Access control boundaries were confirmed â€” test privilege escalation paths and horizontal access across additional tenant contexts."
            )
        else:
            suggestions.append(
                "Compare the same high-value endpoints across public, user, tenant, and admin-style contexts to confirm access boundaries and privilege transitions."
            )
    if "session" in categories:
        suggestions.append(
            "Validate session lifecycle controls end to end, including token reuse across flows, logout invalidation, and consistency of auth enforcement."
        )
    if "business_logic" in categories:
        suggestions.append(
            "Walk critical multi-step workflows manually and test whether state, price, quantity, role, or approval fields can be changed out of order."
        )
    if "payment" in categories:
        suggestions.append(
            "Map checkout, billing, refund, and subscription flows end to end and compare client-visible amounts with server-side ownership and pricing enforcement."
        )
    if "server_side_injection" in categories:
        suggestions.append(
            "Focus on the flagged server-side injection surfaces and compare error handling, file/path parsing, XML parsing, and command-style parameters with safe mutations."
        )
    if "ai_surface" in categories:
        suggestions.append(
            "Review AI-oriented endpoints for model enumeration, prompt exposure, provider keys, and insufficient throttling before assuming the surface is low risk."
        )
    if "redirect" in categories:
        suggestions.append(
            "Trace full redirect chains around login and callback flows and compare how destinations change before versus after authentication."
        )
    if not parameters:
        suggestions.append(
            "Parameter coverage is low, so enable deeper crawling and optional parameter discovery tooling on the next pass."
        )
    if bool(target_profile.get("api_heavy")):
        suggestions.append(
            "The target looks API-heavy, so prioritize authenticated API replay, schema discovery, and ID-based endpoint review."
        )
    detected_techs = {item.get("technology") for item in (technology_summary or [])}
    if "WordPress" in detected_techs:
        suggestions.append(
            "WordPress indicators were detected, so review plugins, backups, wp-json exposure, and upload surfaces."
        )
    if "Next.js" in detected_techs or "React" in detected_techs:
        suggestions.append(
            "Frontend framework markers were detected, so inspect script bundles and client-side routes for hidden endpoints."
        )
    if len(findings) < 5:
        suggestions.append(
            "Signal is light so far, so increase crawl depth or broaden the priority limit for the next run."
        )
    # Add de-escalation hints for confirmed false positives
    for cat in validated_unconfirmed:
        if cat in categories and cat not in validated_confirmed:
            suggestions.append(
                f"{cat.upper()} signals were not confirmed in validation â€” consider reducing focus or adjusting detection thresholds for this category."
            )
    return suggestions[:5]


def build_feedback_targets(
    analysis_results: dict[str, list[dict[str, Any]]], limit: int = 40
) -> list[str]:
    feedback_targets: list[str] = []
    seen: set[str] = set()
    for label in [
        "idor_candidate_finder",
        "ssrf_candidate_finder",
        "token_leak_detector",
        "payment_flow_intelligence",
    ]:
        for item in analysis_results.get(label, []):
            url = str(item.get("url", "")).strip()
            if url and url not in seen:
                seen.add(url)
                feedback_targets.append(url)
            if len(feedback_targets) >= limit:
                break
        if len(feedback_targets) >= limit:
            break
    return feedback_targets


def build_manual_verification_queue(
    findings: list[dict[str, Any]], limit: int = 8
) -> list[dict[str, Any]]:
    """Build a queue of findings that require manual verification."""
    queue = []
    seen_endpoints: set[str] = set()
    for item in findings:
        if item.get("category") not in MANUAL_QUEUE_CATEGORIES:
            continue
        endpoint_key = str(item.get("evidence", {}).get("endpoint_key") or item.get("url", ""))
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)
        replay_id = str(item.get("evidence", {}).get("replay", {}).get("id", ""))
        request_context = item.get("evidence", {}).get("request_context", {})
        proof_bundle = item.get("evidence", {}).get("proof_bundle", {}) or build_proof_bundle(
            item.get("url", ""), request_context
        )
        chain_simulation = item.get("evidence", {}).get(
            "chain_simulation", {}
        ) or build_chain_simulation(
            {
                **(item.get("evidence", {}) or {}),
                "url": item.get("url", ""),
                "category": item.get("category", ""),
                "signals": (item.get("evidence", {}) or {}).get("signals", item.get("signals", [])),
                "request_context": request_context,
            }
        )
        endpoint_type = derive_endpoint_type(item)
        parameter = str(request_context.get("parameter", "")).strip()
        mutated_url = str(request_context.get("mutated_url", "")).strip()
        has_replay_observation = bool(replay_id and parameter and mutated_url)
        is_api_replay_candidate = endpoint_type == "API" and has_replay_observation
        review_brief = build_review_brief(
            item, replay_id, request_context, proof_bundle, chain_simulation
        )
        automation_tasks = build_automation_tasks(
            replay_id=replay_id,
            proof_bundle=proof_bundle,
            endpoint_type=endpoint_type,
            is_api_replay_candidate=is_api_replay_candidate,
        )
        queue.append(
            {
                "title": item.get("title", "Review finding"),
                "url": item.get("url", ""),
                "category": item.get("category", ""),
                "severity": item.get("severity", "info"),
                "confidence": item.get("confidence", 0),
                "history_status": item.get("history_status", "new"),
                "combined_signal": item.get("combined_signal", ""),
                "next_step": item.get("next_step", ""),
                "review_brief": review_brief,
                "replay_id": replay_id,
                "endpoint_type": endpoint_type,
                "has_replay_observation": has_replay_observation,
                "is_api_replay_candidate": is_api_replay_candidate,
                "request_context": request_context,
                "evidence": item.get("evidence", {}) or {},
                "proof_bundle": proof_bundle,
                "chain_simulation": chain_simulation,
                "poc_curl": proof_bundle.get("curl", ""),
                "poc_python": proof_bundle.get("python", ""),
                "chain_summary": chain_simulation.get("summary", ""),
                "automation_tasks": automation_tasks,
            }
        )
        if len(queue) >= limit:
            break
    return queue


def build_high_confidence_shortlist(
    findings: list[dict[str, Any]], limit: int = 5
) -> list[dict[str, Any]]:
    """Build a shortlist of high-confidence findings for immediate attention."""
    shortlist = []
    seen_endpoints: set[str] = set()
    preferred_categories = {
        "idor",
        "ssrf",
        "oauth_flow",
        "open_redirect",
        "token_leak",
        "sensitive_data",
        "anomaly",
        "behavioral_deviation",
        "payment",
        "access_control",
        "session",
        "business_logic",
        "redirect",
        "server_side_injection",
        "ai_surface",
    }
    ordered = sorted(
        findings,
        key=lambda entry: (
            entry.get("category") not in preferred_categories,
            entry.get("endpoint_type") in {"AUTH", "STATIC"},
            -entry.get("confidence", 0.5),
            -entry.get("score", 0),
            entry.get("url", ""),
        ),
    )
    for item in ordered:
        endpoint_key = str(item.get("evidence", {}).get("endpoint_key") or item.get("url", ""))
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)
        shortlist.append(
            {
                "title": item.get("title", "Finding"),
                "url": item.get("url", ""),
                "category": item.get("category", "unknown"),
                "severity": item.get("severity", "info"),
                "confidence": item.get("confidence", 0),
                "history_status": item.get("history_status", "new"),
                "combined_signal": item.get("combined_signal", ""),
                "next_step": item.get("next_step", ""),
            }
        )
        if len(shortlist) >= limit:
            break
    return shortlist


def build_cross_finding_correlation(
    findings: list[dict[str, Any]], limit: int = 15
) -> list[dict[str, Any]]:
    """Identify correlations across findings to reveal attack chains and systemic issues."""
    from urllib.parse import urlparse

    correlations: list[dict[str, Any]] = []
    host_findings: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        url = str(finding.get("url", "")).strip()
        if not url:
            continue
        host = urlparse(url).netloc.lower()
        if host:
            host_findings.setdefault(host, []).append(finding)
    for host, host_items in host_findings.items():
        categories = {item.get("category", "") for item in host_items}
        if len(categories) >= 2:
            high_confidence = [
                item for item in host_items if float(item.get("confidence", 0)) >= 0.7
            ]
            correlation_score = (
                len(categories) * 3 + len(high_confidence) * 2 + min(len(host_items), 10)
            )
            correlations.append(
                {
                    "correlation_type": "host_systemic",
                    "host": host,
                    "finding_count": len(host_items),
                    "category_count": len(categories),
                    "categories": sorted(categories),
                    "high_confidence_count": len(high_confidence),
                    "correlation_score": correlation_score,
                    "explanation": f"Host {host} has {len(categories)} distinct finding categories ({', '.join(sorted(categories)[:4])}) across {len(host_items)} findings, suggesting systemic security posture issues.",
                    "sample_urls": [item.get("url", "") for item in host_items[:5]],
                }
            )
    resource_findings: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        evidence = finding.get("evidence", {}) or {}
        resource = str(evidence.get("resource_group", "")).strip()
        if not resource:
            url = str(finding.get("url", "")).strip()
            path = urlparse(url).path.lower()
            for segment in path.split("/"):
                if segment and segment not in {"api", "v1", "v2", "v3", "rest", "graphql"}:
                    resource = segment
                    break
        if resource:
            resource_findings.setdefault(resource, []).append(finding)
    for resource, resource_items in resource_findings.items():
        if len(resource_items) >= 2:
            categories = {item.get("category", "") for item in resource_items}
            if len(categories) >= 2:
                correlation_score = len(resource_items) * 2 + len(categories) * 4
                correlations.append(
                    {
                        "correlation_type": "resource_cross_category",
                        "resource": resource,
                        "finding_count": len(resource_items),
                        "category_count": len(categories),
                        "categories": sorted(categories),
                        "correlation_score": correlation_score,
                        "explanation": f"Resource '{resource}' has findings across {len(categories)} categories ({', '.join(sorted(categories)[:4])}), indicating potential access control gaps across the resource lifecycle.",
                        "sample_urls": [item.get("url", "") for item in resource_items[:5]],
                    }
                )
    parameter_findings: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        evidence = finding.get("evidence", {}) or {}
        params = evidence.get("parameters", evidence.get("query_keys", []))
        if isinstance(params, list):
            for param in params:
                param_str = str(param).strip().lower()
                if param_str:
                    parameter_findings.setdefault(param_str, []).append(finding)
    for param, param_items in parameter_findings.items():
        if len(param_items) >= 3:
            categories = {item.get("category", "") for item in param_items}
            if len(categories) >= 2:
                correlation_score = len(param_items) + len(categories) * 3
                correlations.append(
                    {
                        "correlation_type": "parameter_cross_endpoint",
                        "parameter": param,
                        "finding_count": len(param_items),
                        "category_count": len(categories),
                        "categories": sorted(categories),
                        "correlation_score": correlation_score,
                        "explanation": f"Parameter '{param}' appears in {len(param_items)} findings across {len(categories)} categories ({', '.join(sorted(categories)[:4])}), suggesting a systemic input validation gap.",
                        "sample_urls": [item.get("url", "") for item in param_items[:5]],
                    }
                )
    correlations.sort(key=lambda c: -c.get("correlation_score", 0))
    return correlations[:limit]
