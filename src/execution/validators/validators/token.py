"""Token exposure analyzer for summarizing and grouping token leak findings.

Analyzes token leak detector results to identify replayable locations,
group findings by endpoint, and recommend validation actions.
"""

from typing import Any

from src.analysis.helpers import replay_likelihood, sort_token_targets, token_location_severity


def analyze_token_exposures(analysis_results: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Analyze and summarize token exposure findings from analysis results.

    Groups token leaks by location and endpoint, identifies replayable
    locations, and provides recommended actions.

    Args:
        analysis_results: Dictionary of analysis plugin results.

    Returns:
        Summary dict with status, counts, locations, replayable targets,
        grouped endpoints, and recommended action.
    """
    findings = analysis_results.get("token_leak_detector", [])
    if not findings:
        return {
            "status": "none",
            "count": 0,
            "locations": {},
            "replayable_locations": [],
            "top_targets": [],
            "grouped_by_endpoint": [],
            "recommended_action": "No token exposure findings were detected.",
        }

    locations: dict[str, int] = {}
    replayable_locations: set[str] = set()
    grouped_by_endpoint: dict[str, dict[str, Any]] = {}

    for item in findings:
        location = str(item.get("location", "unknown")).strip().lower() or "unknown"
        locations[location] = locations.get(location, 0) + 1
        if location in {"response_body", "referer_risk"}:
            replayable_locations.add(location)

        endpoint_key = str(item.get("endpoint_key") or "")
        context_severity = float(item.get("context_severity", 0))
        group = grouped_by_endpoint.setdefault(
            endpoint_key,
            {
                "url": item.get("url", ""),
                "endpoint_key": endpoint_key,
                "location": location,
                "severity": token_location_severity(location),
                "indicators": set(),
                "token_shapes": set(),
                "leak_count": 0,
                "repeat_count": 0,
                "endpoint_type": item.get("endpoint_type", "GENERAL"),
                "context_severity": context_severity,
            },
        )
        group["leak_count"] += int(item.get("leak_count", 1))
        group["repeat_count"] += int(item.get("repeat_count", item.get("leak_count", 1)))
        if location in {"response_body", "referer_risk"}:
            group["location"] = location
            group["severity"] = token_location_severity(location)
        if context_severity > group.get("context_severity", 0):
            group["context_severity"] = context_severity
            if context_severity >= 0.8:
                group["severity"] = "high"
            elif context_severity >= 0.65:
                group["severity"] = "medium"
        for indicator in item.get("indicators", []) or [item.get("indicator", "token")]:
            if indicator:
                group["indicators"].add(indicator)
        for shape in item.get("token_shapes", []):
            if shape:
                group["token_shapes"].add(shape)

    grouped_output = []
    high_replay_jwt_targets = []
    high_risk_token_targets = []
    for group in grouped_by_endpoint.values():
        replay_score = replay_likelihood(
            group["location"], sorted(group["token_shapes"]), group["repeat_count"]
        )
        signals = []
        if group["repeat_count"] > 1:
            signals.append("reused_across_urls")
        if "jwt_like" in group["token_shapes"]:
            signals.append("jwt_like_token")

        # Detect high-risk token types beyond JWT
        high_risk_shapes = {
            "bearer_token",
            "aws_access_key",
            "api_key",
            "github_token",
            "slack_token",
            "stripe_key",
        }
        detected_high_risk = high_risk_shapes & set(group["token_shapes"])
        if detected_high_risk:
            signals.append("high_risk_token_type")

        item = {
            "url": group["url"],
            "endpoint_key": group["endpoint_key"],
            "location": group["location"],
            "severity": group["severity"],
            "indicators": sorted(group["indicators"]),
            "token_shapes": sorted(group["token_shapes"]),
            "leak_count": group["leak_count"],
            "repeat_count": group["repeat_count"],
            "endpoint_type": group["endpoint_type"],
            "replay_likelihood": replay_score,
            "context_severity": group.get("context_severity", 0),
            "signals": signals,
        }
        if "jwt_like_token" in signals and replay_score >= 0.8:
            high_replay_jwt_targets.append(item)
        if detected_high_risk and replay_score >= 0.6:
            high_risk_token_targets.append(item)
        grouped_output.append(item)

    top_targets = sort_token_targets(grouped_output)
    recommended_action = (
        "Review rendered-response and referer token leaks first because they are the most likely to be replayable."
        if replayable_locations
        else "Review query-string token exposure and rotate secrets before any authenticated replay testing."
    )
    return {
        "status": "actionable",
        "count": len(findings),
        "locations": dict(sorted(locations.items())),
        "replayable_locations": sorted(replayable_locations),
        "top_targets": top_targets[:10],
        "grouped_by_endpoint": top_targets[:20],
        "high_replay_jwt_targets": high_replay_jwt_targets[:10],
        "high_risk_token_targets": high_risk_token_targets[:10],
        "recommended_action": recommended_action,
    }
