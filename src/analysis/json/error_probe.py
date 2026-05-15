"""Error-based inference probes for JSON analysis.

Contains functions for probing endpoints with invalid values to extract
backend field names, detect stack traces, SQL errors, framework detection,
and sensitive information leakage in error responses.
Extracted from json_analysis.py for better separation of concerns.
"""

import re
from typing import Any

from src.analysis.helpers import endpoint_base_key, endpoint_signature
from src.analysis.json.support import (
    mutate_error_probe_url as _mutate_error_probe_url,
)

# Error field extraction patterns
ERROR_FIELD_RE = re.compile(
    r"""(?ix)
    (?:unknown|invalid|unexpected|required|allowed|missing|unsupported|expected)\s+
    (?:field|parameter|property|argument|value)?\s*
    ['"]?([a-z_][a-z0-9_-]{1,48})['"]?
    """
)
ERROR_JSON_FIELD_RE = re.compile(
    r"""(?ix)
    "(?:field|parameter|path|query|body)"\s*:\s*"([^"]{1,64})"
    """
)
ERROR_STACK_TRACE_RE = re.compile(
    r"""(?ix)
    (?:at\s+\S+\s+\([^)]+\)|File\s+"[^"]+",\s+line\s+\d+|Traceback\s+\(most\s+recent\s+call\s+last\))
    """
)
ERROR_SQL_RE = re.compile(
    r"""(?ix)
    (?:SQL\s+syntax|mysql_fetch|pg_query|ociexecute|ORA-\d+|SQLite|syntax\s+error\s+near|unexpected\s+token)
    """
)

# Framework-specific error patterns
ERROR_FRAMEWORK_PATTERNS = {
    "django": re.compile(
        r"(?:django\.|Django|WSGIRequest|ImproperlyConfigured|DoesNotExist)", re.IGNORECASE
    ),
    "flask": re.compile(r"(?:flask\.|werkzeug|jinja2|Flask|Blueprint)", re.IGNORECASE),
    "spring": re.compile(
        r"(?:org\.springframework|java\.lang|NullPointerException|ClassNotFoundException)",
        re.IGNORECASE,
    ),
    "express": re.compile(
        r"(?:at\s+\w+\s+\(.*node_modules|Express|Cannot\s+(?:GET|POST|PUT|DELETE))", re.IGNORECASE
    ),
    "laravel": re.compile(r"(?:Illuminate|laravel|Whoops!|Symfony)", re.IGNORECASE),
    "rails": re.compile(
        r"(?:ActionController|ActiveRecord|Ruby|Rails|app/controllers)", re.IGNORECASE
    ),
    "aspnet": re.compile(r"(?:System\.Web|ASP\.NET|Server\s+Error|\.aspx|\.asmx)", re.IGNORECASE),
    "wordpress": re.compile(r"(?:WordPress|wp-content|wp-includes|wpdb)", re.IGNORECASE),
}

# Sensitive information patterns in error responses
ERROR_SENSITIVE_INFO_PATTERNS = {
    "internal_path": re.compile(r"(?:/[a-z_]+/){3,}[a-z_]+\.\w+", re.IGNORECASE),
    "database_connection": re.compile(
        r"(?:mongodb://|postgresql://|mysql://|redis://|amqp://)", re.IGNORECASE
    ),
    "api_key_leak": re.compile(
        r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}",
        re.IGNORECASE,
    ),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", re.IGNORECASE),
    "email_address": re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", re.IGNORECASE
    ),
    "file_path": re.compile(r"(?:[A-Z]:\\|/home/|/var/|/etc/|/tmp/|/usr/)[^\s\"']+", re.IGNORECASE),
}


def error_based_inference(
    priority_urls: list[str], response_cache: Any, limit: int = 24
) -> list[dict[str, Any]]:
    """Probe endpoints with invalid values to extract backend field names and hidden parameter hints.

    Enhanced to detect:
    - Standard error field patterns (unknown/invalid/missing field)
    - JSON error response field references
    - Stack trace exposure (framework-specific)
    - SQL error patterns (potential injection surface)
    - Error severity classification
    """
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        mutation = _mutate_error_probe_url(url)
        if not mutation:
            continue
        mutated_response: dict[str, Any] | None = response_cache.request(
            mutation["mutated_url"], headers={"Cache-Control": "no-cache", "X-Error-Probe": "1"}
        )
        if not mutated_response:
            continue
        body = mutated_response.get("body_text") or ""
        lowered = body.lower()
        status_code = mutated_response.get("status_code", 200)
        # Detect error responses more broadly - include 5xx and error keywords
        has_error_response = (
            status_code >= 400
            or any(
                token in lowered for token in ("error", "invalid", "expected", "missing", "unknown")
            )
            or any(token in lowered for token in ("exception", "traceback", "stack trace"))
        )
        if not has_error_response:
            continue
        # Extract inferred fields from multiple error patterns
        inferred_fields = sorted(
            {match.group(1).lower() for match in ERROR_FIELD_RE.finditer(body)}
        )[:10]
        # Also extract from JSON error responses
        json_fields = sorted(
            {match.group(1).lower() for match in ERROR_JSON_FIELD_RE.finditer(body)}
        )[:10]
        inferred_fields = sorted(set(inferred_fields) | set(json_fields))[:15]
        # Detect stack trace exposure
        has_stack_trace = bool(ERROR_STACK_TRACE_RE.search(body))
        # Detect SQL error patterns
        has_sql_error = bool(ERROR_SQL_RE.search(body))

        # Detect framework-specific error patterns
        detected_frameworks = []
        for framework_name, pattern in ERROR_FRAMEWORK_PATTERNS.items():
            if pattern.search(body):
                detected_frameworks.append(framework_name)

        # Detect sensitive information leakage in errors
        leaked_info_types = []
        for info_type, pattern in ERROR_SENSITIVE_INFO_PATTERNS.items():
            if pattern.search(body):
                leaked_info_types.append(info_type)

        # Classify error severity
        error_severity = "low"
        if has_stack_trace:
            error_severity = "high"
        elif has_sql_error:
            error_severity = "high"
        elif detected_frameworks:
            error_severity = "high"  # Framework detection indicates verbose errors
        elif leaked_info_types:
            error_severity = "high" if len(leaked_info_types) >= 2 else "medium"
        elif status_code >= 500:
            error_severity = "medium"
        elif inferred_fields:
            error_severity = "medium"
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "parameter": mutation["parameter"],
                "mutated_url": mutation["mutated_url"],
                "status_code": status_code,
                "inferred_fields": inferred_fields,
                "error_keywords": sorted(
                    {
                        token
                        for token in ("error", "invalid", "expected", "missing", "unknown")
                        if token in lowered
                    }
                ),
                "has_stack_trace": has_stack_trace,
                "has_sql_error": has_sql_error,
                "detected_frameworks": detected_frameworks,
                "leaked_info_types": leaked_info_types,
                "error_severity": error_severity,
                "signals": sorted(
                    {
                        "error_based_field_inference",
                        "stack_trace_exposure" if has_stack_trace else "",
                        "sql_error_exposure" if has_sql_error else "",
                        "server_error_response" if status_code >= 500 else "",
                        "field_enumeration" if inferred_fields else "",
                    }.union({f"framework:{fw}" for fw in detected_frameworks}).union(
                        {f"leaked_info:{info}" for info in leaked_info_types}
                    )
                ),
            }
        )
    findings.sort(
        key=lambda item: (
            0
            if item["error_severity"] == "high"
            else 1
            if item["error_severity"] == "medium"
            else 2,
            -len(item["inferred_fields"]),
            item["url"],
        )
    )
    return findings
