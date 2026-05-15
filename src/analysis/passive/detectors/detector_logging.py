"""Logging-related security issues detector for OWASP A09: Security Logging and Monitoring Failures.

Passively analyzes URLs and HTTP responses for logging-related security issues including
log file exposure, logging endpoints, sensitive data in URLs that might be logged,
verbose logging headers, and debug logging indicators in responses.
"""

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    is_noise_url,
    normalized_confidence,
)

_LOG_FILE_PATHS = (
    "/logs",
    "/log",
    "/access.log",
    "/error.log",
    "/debug.log",
    "/app.log",
    "/server.log",
    "/application.log",
    "/logfile",
    "/logfiles",
    "/log-files",
    "/log_files",
    "/var/log",
    "/logs/",
    "/log/",
)

_LOGGING_ENDPOINT_PATHS = (
    "/log",
    "/logging",
    "/track",
    "/analytics",
    "/telemetry",
    "/metrics",
    "/monitoring",
    "/audit",
    "/audit-log",
    "/audit-log",
    "/event-log",
    "/activity-log",
    "/error-report",
    "/crash-report",
    "/diagnostics",
    "/health",
    "/healthz",
    "/ready",
    "/status",
)

_SENSITIVE_URL_PATTERNS = re.compile(
    r"(?:password|passwd|pwd|pass|token|access_token|refresh_token|api_key|apikey|"
    r"secret|secret_key|authorization|auth_token|session_id|sessionid|sid|"
    r"credit_card|card_number|ssn|social_security|private_key)="
    r"[^&\s/]{4,}",
    re.IGNORECASE,
)

_VERBOSE_LOGGING_HEADERS = {
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "x-span-id",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-amzn-trace-id",
    "x-cloud-trace-context",
    "x-datadog-trace-id",
    "x-otel-trace-id",
}

_DEBUG_LOGGING_PATTERNS = re.compile(
    r"(?:debug\s*[:=]\s*true|debug\s*mode|logging\s*level\s*[:=]\s*(?:debug|trace|verbose)|"
    r"log\s*level\s*[:=]\s*(?:debug|trace|verbose)|verbose\s*logging|"
    r"debug\s*output|trace\s*enabled|stack\s*trace|traceback|"
    r"request\s*logged|response\s*logged|payload\s*logged|"
    r"sql\s*query\s*logged|query\s*log|slow\s*query\s*log|"
    r"access\s*log|error\s*log|audit\s*log|debug\s*log)",
    re.IGNORECASE,
)

_LOG_CONTENT_PATTERNS = re.compile(
    r"(?:\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+(?:DEBUG|INFO|WARN|ERROR|TRACE)|"
    r"\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4}\]|"
    r"\d{10,}(?:\.\d+)?\s+(?:DEBUG|INFO|WARN|ERROR|TRACE)\s+|"
    r"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/\S+\s+HTTP/\d\.\d\s+\d{3}|"
    r"(?:INFO|DEBUG|WARN|ERROR|FATAL)\s+\[\S+\]\s+-\s+)",
    re.IGNORECASE,
)

_SENSITIVE_DATA_IN_LOG_RE = re.compile(
    r"(?:password|token|secret|key|credit.?card|ssn|social.?security)"
    r"\s*[:=]\s*['\"]?[^\s'\"]{4,}",
    re.IGNORECASE,
)


def _check_log_file_exposure(url: str) -> list[str]:
    """Check URL for log file exposure patterns."""
    signals: list[str] = []
    path = urlparse(url).path.lower()

    if any(p in path for p in _LOG_FILE_PATHS):
        signals.append("log_file_endpoint")

    if path.endswith((".log", ".log.gz", ".log.tar", ".log.zip")):
        signals.append("log_file_extension")

    if "/var/log" in path or "/logs/" in path:
        signals.append("system_log_path")

    return signals


def _check_logging_endpoint(url: str) -> list[str]:
    """Check URL for logging-related endpoint patterns."""
    signals: list[str] = []
    path = urlparse(url).path.lower()

    if any(p in path for p in _LOGGING_ENDPOINT_PATHS):
        signals.append("logging_endpoint")

    if "/audit" in path or "/audit-log" in path:
        signals.append("audit_logging_endpoint")

    if "/telemetry" in path or "/metrics" in path:
        signals.append("telemetry_endpoint")

    return signals


def _check_sensitive_data_in_url(url: str) -> list[str]:
    """Check URL for sensitive data that might be logged."""
    signals: list[str] = []
    url.lower()

    if _SENSITIVE_URL_PATTERNS.search(url):
        signals.append("sensitive_data_in_url")

    parsed = urlparse(url)
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        key_lower = key.lower()
        sensitive_keys = {
            "password",
            "passwd",
            "pwd",
            "pass",
            "token",
            "access_token",
            "refresh_token",
            "api_key",
            "apikey",
            "secret",
            "secret_key",
            "authorization",
            "auth_token",
            "session_id",
            "sessionid",
            "credit_card",
            "card_number",
            "ssn",
            "private_key",
        }
        if key_lower in sensitive_keys and value:
            signals.append(f"sensitive_param_in_url:{key_lower}")

    return signals


def _check_verbose_logging_headers(response: dict[str, Any]) -> list[str]:
    """Check response for verbose logging headers."""
    signals: list[str] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}

    found_headers = _VERBOSE_LOGGING_HEADERS & set(headers.keys())
    if found_headers:
        for header in sorted(found_headers):
            signals.append(f"verbose_logging_header:{header}")

    if "x-response-time" in headers or "x-processing-time" in headers:
        signals.append("timing_header_present")

    if "x-debug" in headers or "x-debug-info" in headers:
        signals.append("debug_header_present")

    return signals


def _check_debug_logging_in_response(response: dict[str, Any]) -> list[str]:
    """Check response body for debug logging indicators."""
    signals: list[str] = []
    body = str(response.get("body_text") or "")

    if not body:
        return signals

    if _DEBUG_LOGGING_PATTERNS.search(body):
        signals.append("debug_logging_indicator")

    if _LOG_CONTENT_PATTERNS.search(body):
        signals.append("log_content_in_response")

    if _SENSITIVE_DATA_IN_LOG_RE.search(body):
        signals.append("sensitive_data_in_log_output")

    return signals


def _calculate_severity(signals: list[str]) -> str:
    critical_indicators = {
        "sensitive_data_in_log_output",
        "sensitive_data_in_url",
    }
    high_indicators = {
        "log_file_endpoint",
        "log_file_extension",
        "system_log_path",
        "debug_logging_indicator",
        "debug_header_present",
    }
    medium_indicators = {
        "logging_endpoint",
        "audit_logging_endpoint",
        "telemetry_endpoint",
        "log_content_in_response",
        "verbose_logging_header:",
        "sensitive_param_in_url:",
    }

    for signal in signals:
        if signal in critical_indicators:
            return "high"
    for signal in signals:
        if signal in high_indicators or any(signal.startswith(ind) for ind in high_indicators):
            return "high"
    for signal in signals:
        if signal in medium_indicators or any(signal.startswith(ind) for ind in medium_indicators):
            return "medium"
    return "low"


def _calculate_risk_score(signals: list[str]) -> int:
    score = 0
    severity_scores: dict[str, int] = {
        "sensitive_data_in_log_output": 9,
        "sensitive_data_in_url": 8,
        "log_file_endpoint": 7,
        "log_file_extension": 7,
        "system_log_path": 6,
        "debug_logging_indicator": 6,
        "debug_header_present": 5,
        "logging_endpoint": 3,
        "audit_logging_endpoint": 3,
        "telemetry_endpoint": 3,
        "log_content_in_response": 5,
        "timing_header_present": 1,
    }

    for signal in signals:
        if signal in severity_scores:
            score += severity_scores[signal]
        elif signal.startswith("verbose_logging_header:"):
            score += 2
        elif signal.startswith("sensitive_param_in_url:"):
            score += 6

    return min(score, 20)


def logging_security_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Detect logging-related security issues passively.

    Analyzes URLs and responses for:
    - Log file exposure (/logs, /log, /access.log, /error.log, /debug.log)
    - Logging endpoints (/log, /logging, /track, /analytics)
    - Sensitive data in URL paths (passwords, tokens in URLs that might be logged)
    - Verbose logging headers (X-Request-ID, X-Correlation-ID patterns)
    - Debug logging indicators in responses
    - Log content exposed in response bodies

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts.
        limit: Maximum number of findings to return.

    Returns:
        List of logging security findings sorted by risk score.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url in sorted(urls):
        if is_noise_url(url):
            continue

        signals: list[str] = []
        signals.extend(_check_log_file_exposure(url))
        signals.extend(_check_logging_endpoint(url))
        signals.extend(_check_sensitive_data_in_url(url))

        if not signals:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(signals)
        risk_score = _calculate_risk_score(signals)
        confidence = normalized_confidence(
            base=0.42,
            score=risk_score,
            signals=signals,
            cap=0.90,
        )

        title_parts: list[str] = []
        if "log_file_endpoint" in signals:
            title_parts.append("Log File Endpoint Detected")
        if "log_file_extension" in signals:
            title_parts.append("Log File Extension in URL")
        if "system_log_path" in signals:
            title_parts.append("System Log Path Exposed")
        if "sensitive_data_in_url" in signals:
            title_parts.append("Sensitive Data in URL")
        if any(s.startswith("sensitive_param_in_url:") for s in signals):
            title_parts.append("Sensitive Parameter in URL")
        if "logging_endpoint" in signals:
            title_parts.append("Logging Endpoint Detected")
        if "telemetry_endpoint" in signals:
            title_parts.append("Telemetry Endpoint Detected")

        title = "; ".join(title_parts) if title_parts else "Logging Security Issue Detected"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        signals: list[str] = []
        signals.extend(_check_verbose_logging_headers(response))
        signals.extend(_check_debug_logging_in_response(response))

        if not signals:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(signals)
        risk_score = _calculate_risk_score(signals)
        confidence = normalized_confidence(
            base=0.42,
            score=risk_score,
            signals=signals,
            cap=0.92,
        )

        title_parts: list[str] = []
        if "debug_logging_indicator" in signals:
            title_parts.append("Debug Logging Detected in Response")
        if "log_content_in_response" in signals:
            title_parts.append("Log Content Exposed in Response")
        if "sensitive_data_in_log_output" in signals:
            title_parts.append("Sensitive Data in Log Output")
        if any(s.startswith("verbose_logging_header:") for s in signals):
            title_parts.append("Verbose Logging Headers Present")
        if "debug_header_present" in signals:
            title_parts.append("Debug Header Present")
        if "timing_header_present" in signals:
            title_parts.append("Timing Header Present")

        title = "; ".join(title_parts) if title_parts else "Logging Response Issue Detected"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    findings.sort(key=lambda item: (-item["risk_score"], item["url"]))
    return findings[:limit]
