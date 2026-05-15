"""Passive security logging detector for OWASP A09: Security Logging and Monitoring Failures.

Analyzes HTTP responses for sensitive data exposure, verbose error messages,
stack traces, debug indicators, and other logging/monitoring failures.

This package modularizes the logging failure detector into separate files
for better maintainability and AI-agent editability.
"""

from typing import Any

from src.analysis.helpers import endpoint_signature, is_noise_url, normalized_confidence

from ._constants import (
    API_SECRET_PATTERNS,
    DB_CONN_PATTERNS,
    DEBUG_INDICATORS,
    ENV_VAR_PATTERNS,
    FILE_PATH_PATTERNS,
    INTERNAL_IP_PATTERN,
    SENSITIVE_QUERY_PARAMS,
    SENSITIVE_VALUE_PATTERNS,
    SQL_ERROR_PATTERNS,
    STACK_TRACE_PATTERNS,
)
from ._helpers import (
    build_finding,
    calculate_risk_score,
    check_api_secrets,
    check_cors_issues,
    check_db_connections,
    check_debug_indicators,
    check_env_vars,
    check_file_paths,
    check_internal_ips,
    check_logging_headers,
    check_sensitive_query_params,
    check_sql_exposure,
    check_stack_traces,
    check_verbose_errors,
    determine_severity,
)

__all__ = [
    "logging_failure_detector",
    "API_SECRET_PATTERNS",
    "DB_CONN_PATTERNS",
    "DEBUG_INDICATORS",
    "ENV_VAR_PATTERNS",
    "FILE_PATH_PATTERNS",
    "INTERNAL_IP_PATTERN",
    "SENSITIVE_QUERY_PARAMS",
    "SENSITIVE_VALUE_PATTERNS",
    "SQL_ERROR_PATTERNS",
    "STACK_TRACE_PATTERNS",
]


def logging_failure_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Detect security logging and monitoring failures (OWASP A09)."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    response_by_url: dict[str, dict[str, Any]] = {}
    for resp in responses:
        resp_url = str(resp.get("url", "")).strip()
        if resp_url:
            response_by_url[resp_url] = resp

    for url in sorted(urls):
        if len(findings) >= limit:
            break
        if is_noise_url(url):
            continue

        param_issues = check_sensitive_query_params(url)
        if not param_issues:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        response = response_by_url.get(url, {})
        body = str(response.get("body_text") or "")
        headers_raw = response.get("headers") or {}
        headers = {str(k).lower(): str(v) for k, v in headers_raw.items()}

        all_issues = list(param_issues)
        all_issues.extend(check_verbose_errors(body))
        all_issues.extend(check_stack_traces(body))
        all_issues.extend(check_debug_indicators(body, headers))
        all_issues.extend(check_sql_exposure(body))
        all_issues.extend(check_internal_ips(body))
        all_issues.extend(check_file_paths(body))
        all_issues.extend(check_env_vars(body))
        all_issues.extend(check_db_connections(body))
        all_issues.extend(check_api_secrets(body))
        all_issues.extend(check_logging_headers(headers))
        all_issues.extend(check_cors_issues(headers))

        if not all_issues:
            continue

        risk_score = calculate_risk_score(all_issues)
        severity = determine_severity(risk_score)
        confidence = normalized_confidence(
            base=0.40,
            score=risk_score,
            signals=[issue.get("type", "") for issue in all_issues],
        )

        findings.append(build_finding(url, all_issues, risk_score, severity, confidence))

    findings.sort(
        key=lambda item: (-item.get("score", 0), -item.get("confidence", 0), item.get("url", ""))
    )
    return findings[:limit]
