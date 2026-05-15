"""Utilities for preventing sensitive data exposure in error messages and logs."""

import re
from typing import Any

_SENSITIVE_HEADER_PATTERNS = [
    re.compile(
        r"^(authorization|cookie|x-api-key|x-secret-key|x-access-token|x-auth-token)$",
        re.IGNORECASE,
    ),
]

_SENSITIVE_VALUE_PATTERNS = [
    re.compile(
        r"(?:api[_-]?key|secret|token|password|passwd|credential|auth)\s*[:=]\s*\S+", re.IGNORECASE
    ),
    re.compile(r"(?:Bearer|Basic|Token)\s+[A-Za-z0-9+/=_\-]+", re.IGNORECASE),
    re.compile(r"(?:key|token|secret|password|api_key)\s*[:=]\s*[A-Za-z0-9+/]{16,}={0,2}"),
    re.compile(r"(?:Bearer|Basic|Token)\s+[A-Za-z0-9+/]{16,}={0,2}", re.IGNORECASE),
]

_STACK_TRACE_PATTERNS = [
    re.compile(r"File\s+\"[^\"]+\", line \d+"),
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"^\s+~?\^+$"),
]

_FILE_PATH_PATTERN = re.compile(r"(?:^|[\s])(?:[A-Za-z]:\\|/)(?:[\w\\/.-]+)", re.MULTILINE)

_CREDENTIAL_PATTERNS = [
    re.compile(r"(?:sk-|ghp_|xox[baprs]-|AKIA)[A-Za-z0-9]+"),
    re.compile(
        r"(?:key|token|secret|password|api_key|auth)\s*[:=]\s*[a-zA-Z0-9]{32,}", re.IGNORECASE
    ),
]


def safe_error_message(exc: Exception) -> str:
    """Return a sanitized error message suitable for external exposure.

    Strips stack traces, file paths, and credential-like patterns from
    exception messages to prevent sensitive data leakage.

    Args:
        exc: The exception to sanitize.

    Returns:
        A cleaned error string safe for user-facing output.
    """
    raw = str(exc)
    message = raw

    for pattern in _STACK_TRACE_PATTERNS:
        message = pattern.sub("", message)

    for match in _FILE_PATH_PATTERN.finditer(message):
        path = match.group(0).strip()
        if any(c in path for c in [".py", ".ts", ".js", "site-packages", "lib/python"]):
            message = message.replace(path, "[path redacted]")

    for pattern in _CREDENTIAL_PATTERNS:
        message = pattern.sub("[credential redacted]", message)

    for pattern in _SENSITIVE_VALUE_PATTERNS:
        sensitive_match = pattern.search(message)
        if sensitive_match:
            matched_text = sensitive_match.group(0)
            if "=" in matched_text:
                key, _ = matched_text.rsplit("=", 1)
                message = message.replace(matched_text, f"{key}=[redacted]")
            elif ":" in matched_text:
                key, _ = matched_text.rsplit(":", 1)
                message = message.replace(matched_text, f"{key}: [redacted]")
            else:
                message = message.replace(matched_text, "[redacted]")

    message = message.strip()

    if not message:
        return "An unexpected error occurred"

    return message


def sanitize_log_message(message: str) -> str:
    """Redact sensitive values from a log message string.

    Specifically targets Authorization, Cookie, and X-API-Key header
    values as well as common credential-like patterns.

    Args:
        message: The log message to sanitize.

    Returns:
        The message with sensitive values replaced by [REDACTED].
    """
    result = message

    bearer_pattern = re.compile(r"(Bearer\s+)\S+", re.IGNORECASE)
    result = bearer_pattern.sub(r"\1[REDACTED]", result)

    basic_pattern = re.compile(r"(Basic\s+)\S+", re.IGNORECASE)
    result = basic_pattern.sub(r"\1[REDACTED]", result)

    header_value_pattern = re.compile(
        r"((?:authorization|cookie|x-api-key|x-secret-key|x-access-token|x-auth-token)\s*[:=]\s*)(?:(?:Bearer|Basic|Token)\s+)?(.+?)(?:\s+(?:and|or|,)\s|$)",
        re.IGNORECASE,
    )
    result = header_value_pattern.sub(r"\1[REDACTED]", result)

    for pattern in _CREDENTIAL_PATTERNS:
        result = pattern.sub("[REDACTED]", result)

    return result


def redact_sensitive_headers(headers: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of headers dict with sensitive values redacted.

    Args:
        headers: Original headers dictionary.

    Returns:
        New dictionary with sensitive header values replaced by "[REDACTED]".
    """
    redacted: dict[str, Any] = {}
    for key, value in headers.items():
        is_sensitive = False
        for pattern in _SENSITIVE_HEADER_PATTERNS:
            if pattern.match(key):
                is_sensitive = True
                break
        if is_sensitive:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted
