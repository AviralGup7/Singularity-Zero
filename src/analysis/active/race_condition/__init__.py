"""Active race condition probe for OWASP A08: Data Integrity Failures.

Detects race condition vulnerabilities by sending concurrent requests to
stateful endpoints and analyzing response inconsistencies, duplicate
processing, TOCTOU flaws, and state transition anomalies.

This package modularizes the race condition probe into separate files
for better maintainability and AI-agent editability.
"""

from typing import Any

from src.analysis.helpers import endpoint_signature

from ._constants import RACE_PROBE_SPEC
from ._helpers import (
    build_finding,
    calculate_confidence,
    calculate_severity,
    classify_race_type,
    detect_balance_changes,
    detect_duplicate_processing,
    detect_response_inconsistency,
    detect_timing_discrepancy,
    detect_toctou,
    extract_json_value,
    is_race_prone_endpoint,
    make_concurrent_requests,
)

__all__ = ["race_condition_probe", "RACE_PROBE_SPEC"]


def race_condition_probe(
    priority_urls: list[str],
    response_cache: Any,
    limit: int = 12,
    concurrent_requests: int = 10,
) -> list[dict[str, Any]]:
    """Detect race condition vulnerabilities via concurrent request analysis."""
    findings: list[dict[str, Any]] = []
    seen_endpoints: set[str] = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        is_prone, race_category = is_race_prone_endpoint(url)
        if not is_prone:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)

        race_type = classify_race_type(url)
        issues: list[str] = []
        evidence: list[dict[str, Any]] = []

        responses = make_concurrent_requests(response_cache, url, count=concurrent_requests)
        if not responses:
            continue

        inconsistent = detect_response_inconsistency(responses)
        if inconsistent:
            issues.append("inconsistent_responses")
            evidence.extend(inconsistent)

        duplicates = detect_duplicate_processing(responses)
        if duplicates:
            issues.append("duplicate_processing")
            evidence.extend(duplicates)

        toctou = detect_toctou(responses)
        if toctou:
            issues.append("toctou_vulnerability")
            evidence.extend(toctou)

        balance = detect_balance_changes(responses)
        if balance:
            issues.append("balance_inconsistency")
            evidence.extend(balance)

        timing = detect_timing_discrepancy(responses)
        if timing:
            issues.append("timing_discrepancy")
            evidence.extend(timing)

        if race_category == "auth_flow":
            auth_success = sum(1 for r in responses if 200 <= int(r.get("status_code") or 0) < 300)
            if auth_success > 1:
                issues.append("auth_race_condition")
                evidence.append(
                    {
                        "type": "auth_race_condition",
                        "concurrent_successes": auth_success,
                        "description": "Multiple concurrent authentication attempts succeeded",
                    }
                )

        if race_category == "state_transition":
            statuses = {
                extract_json_value(str(r.get("body_text", "")), "status") for r in responses
            }
            statuses.discard(None)
            if len(statuses) > 1:
                issues.append("state_transition_race")
                evidence.append(
                    {
                        "type": "state_transition_race",
                        "observed_statuses": sorted(str(s) for s in statuses),
                        "description": "Concurrent requests resulted in different state transitions",
                    }
                )

        if race_category == "resource_allocation":
            success_count = sum(1 for r in responses if 200 <= int(r.get("status_code") or 0) < 300)
            if success_count > 1:
                issues.append("resource_allocation_race")
                evidence.append(
                    {
                        "type": "resource_allocation_race",
                        "concurrent_allocations": success_count,
                        "description": "Multiple concurrent resource allocations succeeded",
                    }
                )

        if not issues:
            continue

        confidence = calculate_confidence(issues)
        severity = calculate_severity(issues)

        findings.append(build_finding(url, race_type, issues, evidence, confidence, severity))

    findings.sort(
        key=lambda item: (-item.get("score", 0), -item.get("confidence", 0), item.get("url", ""))
    )
    return findings[:limit]
