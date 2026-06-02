"""Helper functions for security logging failure detection."""

from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
)
from src.analysis.passive.runtime import looks_random

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


def check_sensitive_query_params(url: str) -> list[dict[str, str]]:
    """Check URL query parameters for sensitive data."""
    issues: list[dict[str, str]] = []
    parsed = urlparse(url)
    if not parsed.query:
        return issues
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        key_lower = key.lower().strip()
        if key_lower in SENSITIVE_QUERY_PARAMS:
            redacted = value[:4] + "..." + value[-4:] if len(value) > 8 else "[REDACTED]"
            issues.append(
                {
                    "type": "sensitive_query_param",
                    "param": key_lower,
                    "evidence": f"Sensitive parameter '{key_lower}' in URL with value '{redacted}'",
                }
            )
        for pattern_name, pattern in SENSITIVE_VALUE_PATTERNS.items():
            if pattern.search(value):
                issues.append(
                    {
                        "type": "sensitive_value_in_param",
                        "param": key_lower,
                        "pattern": pattern_name,
                        "evidence": f"Sensitive data pattern '{pattern_name}' found in parameter '{key_lower}'",
                    }
                )
    return issues


def check_verbose_errors(body: str) -> list[dict[str, str]]:
    """Check response body for verbose error messages."""
    issues: list[dict[str, str]] = []
    body_lower = body.lower()
    verbose_indicators = [
        ("internal_server_error_detail", "Detailed internal error information exposed"),
        ("exception_details", "Exception details visible in response"),
        ("error_message_contains_path", "File path exposed in error message"),
        ("sql_query_in_response", "SQL query visible in response body"),
        ("database_error_detail", "Database-specific error details exposed"),
        ("server_version_exposed", "Server version information disclosed"),
        ("framework_error_page", "Framework default error page detected"),
    ]
    for indicator, description in verbose_indicators:
        if indicator.replace("_", " ") in body_lower or indicator.replace("_", "") in body_lower:
            issues.append(
                {"type": "verbose_error", "indicator": indicator, "evidence": description}
            )
    return issues


def check_stack_traces(body: str) -> list[dict[str, str]]:
    """Check response body for stack traces."""
    issues: list[dict[str, str]] = []
    for trace_name, pattern in STACK_TRACE_PATTERNS.items():
        match = pattern.search(body)
        if match:
            snippet = body[match.start() : match.start() + 120].replace("\n", " ").replace("\r", "")
            issues.append(
                {
                    "type": "stack_trace",
                    "trace_type": trace_name,
                    "evidence": f"Stack trace detected ({trace_name}): ...{snippet[:100]}...",
                }
            )
    return issues


def check_debug_indicators(body: str, headers: dict[str, str]) -> list[dict[str, str]]:
    """Check for debug mode indicators."""
    issues: list[dict[str, str]] = []
    for indicator_name, pattern in DEBUG_INDICATORS.items():
        if pattern.search(body):
            issues.append(
                {
                    "type": "debug_indicator",
                    "indicator": indicator_name,
                    "evidence": f"Debug mode indicator found: {indicator_name}",
                }
            )
    if headers.get("x-debug", "").lower() in ("true", "1", "yes", "on"):
        issues.append(
            {
                "type": "debug_header",
                "indicator": "x_debug_header",
                "evidence": "X-Debug header present and enabled",
            }
        )
    return issues


def check_sql_exposure(body: str) -> list[dict[str, str]]:
    """Check for SQL queries exposed in error responses."""
    issues: list[dict[str, str]] = []
    for sql_name, pattern in SQL_ERROR_PATTERNS.items():
        match = pattern.search(body)
        if match:
            snippet = body[match.start() : match.start() + 120].replace("\n", " ").replace("\r", "")
            issues.append(
                {
                    "type": "sql_exposure",
                    "sql_type": sql_name,
                    "evidence": f"SQL-related information exposed ({sql_name}): ...{snippet[:100]}...",
                }
            )
    return issues


def check_internal_ips(body: str) -> list[dict[str, str]]:
    """Check for internal IP addresses in response body."""
    issues: list[dict[str, str]] = []
    matches = INTERNAL_IP_PATTERN.findall(body)
    unique_ips = set(matches)
    if unique_ips:
        display_ips = sorted(unique_ips)[:5]
        issues.append(
            {
                "type": "internal_ip_leak",
                "ips": ", ".join(display_ips),
                "evidence": f"Internal IP addresses exposed in response: {', '.join(display_ips)}",
            }
        )
    return issues


def check_file_paths(body: str) -> list[dict[str, str]]:
    """Check for file paths exposed in error messages."""
    issues: list[dict[str, str]] = []
    for path_name, pattern in FILE_PATH_PATTERNS.items():
        match = pattern.search(body)
        if match:
            issues.append(
                {
                    "type": "file_path_exposure",
                    "path_type": path_name,
                    "evidence": f"File path exposed ({path_name}): ...{match.group()[:80]}...",
                }
            )
    return issues


def check_env_vars(body: str) -> list[dict[str, str]]:
    """Check for environment variable leaks."""
    issues: list[dict[str, str]] = []
    for env_name, pattern in ENV_VAR_PATTERNS.items():
        match = pattern.search(body)
        if match:
            snippet = body[match.start() : match.start() + 100].replace("\n", " ").replace("\r", "")
            issues.append(
                {
                    "type": "env_var_leak",
                    "env_type": env_name,
                    "evidence": f"Environment variable leak detected ({env_name}): ...{snippet[:80]}...",
                }
            )
    return issues


def check_db_connections(body: str) -> list[dict[str, str]]:
    """Check for database connection strings exposed."""
    issues: list[dict[str, str]] = []
    for db_name, pattern in DB_CONN_PATTERNS.items():
        match = pattern.search(body)
        if match:
            conn_str = match.group()
            redacted = (
                conn_str.split("://")[0] + "://[REDACTED]" if "://" in conn_str else "[REDACTED]"
            )
            issues.append(
                {
                    "type": "db_connection_leak",
                    "db_type": db_name,
                    "evidence": f"Database connection string exposed ({db_name}): {redacted}",
                }
            )
    return issues


def check_api_secrets(body: str) -> list[dict[str, str]]:
    """Check for API keys/secrets in response body."""
    issues: list[dict[str, str]] = []
    for secret_name, pattern in API_SECRET_PATTERNS.items():
        match = pattern.search(body)
        if match:
            matched_value = match.group()
            redacted = (
                matched_value[:6] + "..." + matched_value[-4:]
                if len(matched_value) > 10
                else "[REDACTED]"
            )
            issues.append(
                {
                    "type": "api_secret_exposure",
                    "secret_type": secret_name,
                    "evidence": f"API key/secret exposed ({secret_name}): {redacted}",
                }
            )
    return issues


def check_logging_headers(headers: dict[str, str]) -> list[dict[str, str]]:
    """Check for logging-related header issues."""
    issues: list[dict[str, str]] = []
    if "x-request-id" in headers:
        request_id = headers["x-request-id"]
        if len(request_id) < 16 or not looks_random(request_id):
            issues.append(
                {
                    "type": "weak_request_id",
                    "evidence": f"X-Request-ID present but appears predictable: '{request_id[:20]}...'",
                }
            )
    if "x-response-time" in headers:
        issues.append(
            {
                "type": "timing_header_exposed",
                "evidence": f"X-Response-Time header exposes server timing: {headers['x-response-time']}",
            }
        )
    if "x-powered-by" in headers:
        issues.append(
            {
                "type": "server_info_header",
                "evidence": f"X-Powered-By header reveals technology: {headers['x-powered-by']}",
            }
        )
    if "server" in headers:
        server_val = headers["server"].lower()
        if any(token in server_val for token in ("debug", "dev", "development", "test")):
            issues.append(
                {
                    "type": "debug_server_header",
                    "evidence": f"Server header indicates debug/dev mode: {headers['server']}",
                }
            )
    return issues


def check_cors_issues(headers: dict[str, str]) -> list[dict[str, str]]:
    """Check for CORS misconfigurations related to logging/monitoring."""
    issues: list[dict[str, str]] = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        issues.append(
            {
                "type": "cors_wildcard_with_credentials",
                "evidence": "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
            }
        )
    if acao == "*" and any(
        h in headers for h in ("access-control-allow-headers", "access-control-allow-methods")
    ):
        allowed_headers = headers.get("access-control-allow-headers", "")
        sensitive_headers = {"authorization", "x-api-key", "x-auth-token", "cookie", "x-csrf-token"}
        if sensitive_headers & set(h.lower().strip() for h in allowed_headers.split(",")):
            issues.append(
                {
                    "type": "cors_wildcard_sensitive_headers",
                    "evidence": f"Wildcard CORS with sensitive headers allowed: {allowed_headers[:100]}",
                }
            )
    return issues


def calculate_risk_score(issues: list[dict[str, str]]) -> int:
    """Calculate a risk score based on detected issues."""
    score = 0
    issue_types = {issue.get("type", "") for issue in issues}
    scoring = {
        "sensitive_query_param": 4,
        "sensitive_value_in_param": 5,
        "stack_trace": 5,
        "debug_indicator": 4,
        "debug_header": 3,
        "sql_exposure": 6,
        "internal_ip_leak": 3,
        "file_path_exposure": 3,
        "env_var_leak": 6,
        "db_connection_leak": 8,
        "api_secret_exposure": 7,
        "weak_request_id": 2,
        "timing_header_exposed": 1,
        "server_info_header": 1,
        "debug_server_header": 3,
        "cors_wildcard_with_credentials": 5,
        "cors_wildcard_sensitive_headers": 4,
        "verbose_error": 2,
    }
    for issue_type in issue_types:
        score += scoring.get(issue_type, 1)
    return score


def determine_severity(score: int) -> str:
    """Determine severity level from risk score."""
    if score >= 12:
        return "critical"
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def build_finding(
    url: str, issues: list[dict[str, str]], risk_score: int, severity: str, confidence: float
) -> dict[str, Any]:
    """Build a standardized finding dict."""
    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "category": "logging_failure",
        "title": f"Security logging and monitoring failures detected: {url}",
        "severity": severity,
        "confidence": round(confidence, 2),
        "score": risk_score,
        "signals": sorted({issue.get("type", "") for issue in issues} - {""}),
        "evidence": {"issues": issues, "risk_score": risk_score},
        "explanation": (
            f"Endpoint '{url}' exhibits {len(issues)} security logging/monitoring failures "
            f"including sensitive data exposure, verbose errors, and debug indicators. "
            f"Risk score: {risk_score}."
        ),
    }
