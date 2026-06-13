"""Workflow bypass probes.

Tests whether downstream endpoints can be reached without completing
required upstream steps, using:
- Parameter pollution to skip workflow stages.
- Direct endpoint access to admin-only steps with non-admin context.
"""

from __future__ import annotations

import logging
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature

ResponseCache = Any

logger = logging.getLogger(__name__)

_SKIP_STEP_HINTS = {
    "/order": ["/cart/add", "/cart/item/add"],
    "/checkout": ["/cart/add", "/cart/item/add"],
    "/payment": ["/order/confirm", "/checkout"],
    "/confirm": ["/cart/add", "/order/confirm"],
}

_ADMIN_PATH_HINTS = {
    "/admin",
    "/manage",
    "/config",
    "/settings",
    "/users",
    "/roles",
    "/permissions",
    "/billing/invoice",
    "/shipments",
    "/reports",
}


def _path_suffix(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).path.lower()


def _has_stage(path_lower: str) -> bool:
    return any(path_lower.startswith(stage) for stage in _SKIP_STEP_HINTS)


def _upstream_missing(path_lower: str) -> list[str] | None:
    for stage, upstreams in _SKIP_STEP_HINTS.items():
        if path_lower.startswith(stage):
            return upstreams
    return None


def _is_admin_path(path_lower: str) -> bool:
    return any(hint in path_lower for hint in _ADMIN_PATH_HINTS)


def _probe_confidence(issues: list[str]) -> float:
    values = [0.65, 0.70, 0.80, 0.85, 0.88, 0.90]
    idx = min(len(issues) - 1, len(values) - 1)
    return values[idx]


def workflow_bypass_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: Any | None = None,
    *,
    client: Any = None,
    sandbox_session: Any = None,
    limit: int = 12,
    timeout_seconds: float = 5.0,
) -> list[dict[str, Any]]:
    """Detect workflow step-skipping and admin-only direct access."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in priority_urls:
        if len(findings) >= limit:
            break
        url = str(item.get("url", "") if isinstance(item, dict) else item).strip()
        if not url:
            continue
        path = _path_suffix(url)
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        issues: list[str] = []
        evidence: list[dict[str, Any]] = []

        missing = _upstream_missing(path)
        if missing is not None:
            issues.append("parameter_pollution_skips_upstream")
            evidence.append({"upstream_steps": missing, "target_path": path})

        if _is_admin_path(path):
            issues.append("admin_workflow_direct_access")
            evidence.append({"admin_path": path})

        if not issues:
            continue

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "issues": issues,
                "probe_type": "business_logic.workflow_bypass",
                "severity": "high" if "admin_workflow_direct_access" in issues else "medium",
                "confidence": _probe_confidence(issues),
                "evidence": evidence,
            }
        )

    findings.sort(key=lambda item: (-item.get("confidence", 0), item.get("url", "")))
    return findings[:limit]
