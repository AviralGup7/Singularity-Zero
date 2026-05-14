"""Finding history annotation and endpoint risk profiles."""

import json
import logging
from pathlib import Path
from typing import Any

from src.analysis.intelligence.findings_dedup import finding_key
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


def _finding_key(item: dict[str, Any]) -> str:
    return finding_key(item)


def _build_endpoint_risk_profiles(
    previous_findings: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Build risk profiles for endpoints based on historical findings."""
    profiles: dict[str, dict[str, Any]] = {}
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for finding in previous_findings:
        if not isinstance(finding, dict):
            continue
        endpoint_key = str(
            (finding.get("evidence", {}) or {}).get("endpoint_base_key")
            or (finding.get("evidence", {}) or {}).get("endpoint_key")
            or finding.get("url", "")
        )
        if not endpoint_key:
            continue

        severity = str(finding.get("severity", "info")).lower()
        category = str(finding.get("category", ""))
        severity_score = severity_order.get(severity, 0)

        if endpoint_key not in profiles:
            profiles[endpoint_key] = {
                "finding_count": 0,
                "max_severity": severity,
                "max_severity_score": severity_score,
                "categories": set(),
                "recurrence_count": 0,
                "last_severity": severity,
                "risk_score": 0,
            }

        profile = profiles[endpoint_key]
        profile["finding_count"] += 1
        profile["categories"].add(category)
        profile["last_severity"] = severity

        if severity_score > profile["max_severity_score"]:
            profile["max_severity"] = severity
            profile["max_severity_score"] = severity_score

    for endpoint_key, profile in profiles.items():
        risk_score = profile["max_severity_score"] * 20
        risk_score += min(profile["finding_count"] * 5, 20)
        risk_score += min(len(profile["categories"]) * 8, 24)
        profile["risk_score"] = min(risk_score, 100)
        profile["categories"] = sorted(profile["categories"])

    return profiles


def annotate_finding_history(
    previous_run: Path | None, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Annotate findings with history status (new vs existing from previous run)."""
    previous_keys: set[str] = set()
    previous_findings: list[dict[str, Any]] = []
    if previous_run is not None and (previous_run / "findings.json").exists():
        try:
            previous_findings = json.loads(
                (previous_run / "findings.json").read_text(encoding="utf-8")
            )
            previous_keys = {
                _finding_key(item) for item in previous_findings if isinstance(item, dict)
            }
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load previous findings for history annotation: %s", exc)
            previous_keys = set()

    endpoint_risk_profiles = _build_endpoint_risk_profiles(previous_findings)

    annotated = []
    for item in findings:
        history_status = "existing" if _finding_key(item) in previous_keys else "new"
        endpoint_key = str(
            (item.get("evidence", {}) or {}).get("endpoint_base_key")
            or (item.get("evidence", {}) or {}).get("endpoint_key")
            or item.get("url", "")
        )
        risk_profile = endpoint_risk_profiles.get(endpoint_key, {})

        risk_trajectory = "unknown"
        if history_status == "existing" and risk_profile:
            prev_severity = risk_profile.get("last_severity", "")
            curr_severity = str(item.get("severity", "")).lower()
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            prev_score = severity_order.get(prev_severity, 0)
            curr_score = severity_order.get(curr_severity, 0)
            if curr_score > prev_score:
                risk_trajectory = "escalating"
            elif curr_score < prev_score:
                risk_trajectory = "improving"
            else:
                risk_trajectory = "stable"
        elif history_status == "new" and risk_profile:
            risk_trajectory = "new_finding_on_risky_endpoint"
        elif history_status == "new":
            risk_trajectory = "new_endpoint"

        annotated.append(
            {
                **item,
                "history_status": history_status,
                "endpoint_risk_profile": risk_profile,
                "risk_trajectory": risk_trajectory,
            }
        )
    return annotated
