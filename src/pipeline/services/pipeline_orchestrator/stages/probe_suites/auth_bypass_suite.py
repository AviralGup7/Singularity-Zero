"""Auth Bypass probe suite runner."""

from __future__ import annotations

from typing import Any


def _run_auth_bypass_suite(
    priority_items: list[dict[str, Any]],
    shared_response_cache: Any,
    limit: int = 12,
    *,
    probes: dict[str, Any],
) -> list[dict[str, Any]]:
    suite_results = probes["run_auth_bypass_probes"](
        priority_items,
        shared_response_cache,
        config={
            "jwt_stripping_limit": max(4, limit // 2),
            "cookie_manipulation_limit": max(4, limit // 2),
            "auth_bypass_limit": max(4, limit // 2),
            "credential_stuffing_limit": max(2, limit // 4),
            "mfa_bypass_limit": max(2, limit // 4),
            "password_reset_abuse_limit": max(2, limit // 4),
        },
    )
    if not isinstance(suite_results, dict):
        return []

    flattened: list[dict[str, Any]] = []
    for suite_name, suite_findings in suite_results.items():
        if not isinstance(suite_findings, list):
            continue
        for finding in suite_findings:
            if len(flattened) >= limit:
                return flattened
            item = dict(finding) if isinstance(finding, dict) else {"value": finding}
            item.setdefault("probe_type", suite_name)
            issues = item.get("issues")
            if not isinstance(issues, list) or not issues:
                item["issues"] = [f"{suite_name}_signal"]
            item.setdefault("confidence", 0.55)
            item.setdefault("severity", "medium")
            # The previous implementation unconditionally copied
            # ``fallback_url`` (the first priority item's URL) into any
            # finding missing a URL. This caused auth-bypass findings
            # from suite 3 to be reported as occurring on the very
            # first target URL, regardless of where the bypass actually
            # was. We now mark such findings as needing manual
            # attribution instead.
            if not str(item.get("url", "")).strip():
                item["needs_attribution"] = True
                if item.get("target_host"):
                    item["url"] = ""
            flattened.append(item)
    return flattened[:limit]
