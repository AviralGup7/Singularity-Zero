"""JSON probe suite runner."""

from __future__ import annotations

from typing import Any


def _run_json_probe_suite(
    priority_urls: list[str],
    shared_response_cache: Any,
    limit: int = 24,
    *,
    probes: dict[str, Any],
) -> list[dict[str, Any]]:
    if not priority_urls:
        return []

    findings: list[dict[str, Any]] = []
    probe_runs = [
        (
            "json_state_transition",
            probes["state_transition_analyzer"](
                priority_urls,
                shared_response_cache,
                max(6, limit // 2),
            ),
        ),
        (
            "json_parameter_dependency",
            probes["parameter_dependency_tracker"](
                priority_urls,
                shared_response_cache,
                max(6, limit // 2),
            ),
        ),
        (
            "json_pagination",
            probes["pagination_walker"](
                priority_urls,
                shared_response_cache,
                max(6, limit // 2),
            ),
        ),
        (
            "json_filter_fuzz",
            probes["filter_parameter_fuzzer"](
                priority_urls,
                shared_response_cache,
                max(6, limit // 2),
            ),
        ),
    ]

    for probe_name, probe_findings in probe_runs:
        if not isinstance(probe_findings, list):
            continue
        for finding in probe_findings:
            if len(findings) >= limit:
                return findings
            item = dict(finding) if isinstance(finding, dict) else {"value": finding}
            item.setdefault("probe", probe_name)
            findings.append(item)
    return findings[:limit]
