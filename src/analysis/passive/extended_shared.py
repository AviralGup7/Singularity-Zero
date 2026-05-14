"""Extended passive analysis checks for XSS, GraphQL, OpenAPI, AI models, and more.

Provides signal detection functions for reflected XSS probes, GraphQL
introspection exposure, OpenAPI/Swagger disclosure, AI model fingerprinting,
SQL/XML/file/command error detection, and third-party key exposure.
"""

import re
from collections.abc import Callable
from typing import Any

# XSS utilities extracted to xss_utils.py
from src.analysis.active.xss_constants import (
    XSS_DANGEROUS_VALUE_RE,
    XSS_FIELD_RE,
)
from src.analysis.active.xss_utils import (
    build_reflection_probe_mutation,
    reflection_context_signals,
    xss_signals,
)
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature

__all__ = [
    "AI_MODEL_RE",
    "AI_PATH_TOKENS",
    "COMMAND_ERROR_RE",
    "COMMAND_PARAM_NAMES",
    "FILE_ERROR_RE",
    "FILE_PARAM_NAMES",
    "GRAPHQL_ERROR_RE",
    "GRAPHQL_INTROSPECTION_RE",
    "OPENAPI_RE",
    "RACE_BODY_KEYWORDS",
    "RACE_PARAM_NAMES",
    "RACE_PATH_KEYWORDS",
    "SQL_ERROR_RE",
    "SQL_PARAM_NAMES",
    "STACK_RE",
    "THIRD_PARTY_KEY_PATTERNS",
    "XML_ERROR_RE",
    "XML_PARAM_NAMES",
    "XSS_DANGEROUS_VALUE_RE",
    "XSS_FIELD_RE",
    "build_reflection_probe_mutation",
    "build_response_index",
    "compute_severity",
    "record",
    "reflection_context_signals",
    "scan_responses",
    "scan_urls_and_responses",
    "xss_signals",
]

# Lazy import to avoid circular dependency through json_analysis_support -> passive_analysis_runtime -> recon
EMAIL_RE = None  # Initialized on first use via _get_email_re()


def _get_email_re() -> re.Pattern[str] | None:
    global EMAIL_RE
    if EMAIL_RE is None:
        from src.analysis.json.support import EMAIL_VALUE_RE

        EMAIL_RE = EMAIL_VALUE_RE
    return EMAIL_RE


# GraphQL detection patterns
GRAPHQL_INTROSPECTION_RE = re.compile(r"__schema|__type|__typename|introspection", re.IGNORECASE)
AI_MODEL_RE = re.compile(
    r"(?:gpt-|claude-|gemini-|llama-|mistral-|model[-_]?id|model[-_]?name)[\w.-]+", re.IGNORECASE
)
GRAPHQL_ERROR_RE = re.compile(
    r"graphql.*error|cannot\s+query|unknown\s+field|validation\s+error", re.IGNORECASE
)

# OpenAPI/Swagger detection pattern
OPENAPI_RE = re.compile(
    r"openapi:\s*['\"]?3\.|swagger:\s*['\"]?2\.|\"swagger\":|\"openapi\":", re.IGNORECASE
)

# Stack trace detection pattern
STACK_RE = re.compile(
    r"traceback|stack\s*trace|at\s+\S+\.\S+\(|file\s+\"[^\"]+\", line \d+", re.IGNORECASE
)

# Third-party key patterns - imported from api_key_candidates
THIRD_PARTY_KEY_PATTERNS: tuple[
    tuple[str, re.Pattern[str]], ...
] = ()  # Will be populated from api_key_candidates on first use

# Additional constants needed by checks/active/_impl.py
AI_PATH_TOKENS = (
    "/ai/",
    "/chat",
    "/completion",
    "/generate",
    "/model",
    "/predict",
    "/embeddings",
    "/inference",
)
COMMAND_ERROR_RE = re.compile(
    r"command not found|/bin/sh|/bin/bash|cmd\.exe|powershell|permission denied", re.IGNORECASE
)
COMMAND_PARAM_NAMES = {
    "cmd",
    "command",
    "exec",
    "execute",
    "run",
    "shell",
    "system",
    "process",
    "action",
    "do",
    "call",
    "invoke",
    "eval",
}
FILE_ERROR_RE = re.compile(
    r"failed to open stream|include\(|require\(|no such file|directory traversal|/etc/passwd",
    re.IGNORECASE,
)
FILE_PARAM_NAMES = {
    "file",
    "path",
    "document",
    "attachment",
    "download",
    "include",
    "page",
    "template",
    "src",
    "load",
    "read",
    "open",
    "import",
    "fetch",
}
RACE_BODY_KEYWORDS = (
    "quantity",
    "amount",
    "price",
    "cost",
    "total",
    "balance",
    "transfer",
    "withdraw",
    "deposit",
    "payment",
    "purchase",
    "order",
    "booking",
    "reserve",
    "claim",
    "redeem",
)
RACE_PARAM_NAMES = {
    "quantity",
    "amount",
    "price",
    "cost",
    "total",
    "balance",
    "transfer",
    "withdraw",
    "deposit",
    "payment",
    "purchase",
    "order",
    "booking",
    "reserve",
    "claim",
    "redeem",
    "coupon",
    "voucher",
    "discount",
    "credit",
    "points",
    "tokens",
}
RACE_PATH_KEYWORDS = (
    "/transfer",
    "/withdraw",
    "/deposit",
    "/payment",
    "/purchase",
    "/order",
    "/booking",
    "/reserve",
    "/claim",
    "/redeem",
    "/apply",
    "/submit",
    "/checkout",
    "/pay",
    "/buy",
)
SQL_ERROR_RE = re.compile(
    r"sql syntax|sqlstate|mysql|postgres|sqlite|ora-\d{4,}|odbc|jdbc|unclosed quotation mark",
    re.IGNORECASE,
)
SQL_PARAM_NAMES = {
    "query",
    "sql",
    "search",
    "filter",
    "sort",
    "order",
    "select",
    "where",
    "from",
    "join",
    "group",
    "having",
    "limit",
    "offset",
    "column",
    "table",
    "database",
    "db",
    "schema",
}
XML_PARAM_NAMES = {
    "xml",
    "xmldata",
    "xmlinput",
    "xmlfile",
    "xmlcontent",
    "xmlpayload",
    "soap",
    "envelope",
    "body",
    "header",
    "element",
    "attribute",
    "namespace",
    "schema",
    "dtd",
}
XML_ERROR_RE = re.compile(
    r"xml parser|saxparse|doctype|external entity|libxml|expat|systemliteral", re.IGNORECASE
)


def _get_third_party_key_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    global THIRD_PARTY_KEY_PATTERNS
    if not THIRD_PARTY_KEY_PATTERNS:
        try:
            from src.api_tests.apitester.api_key_candidates import THIRD_PARTY_KEY_PATTERNS as TPP

            THIRD_PARTY_KEY_PATTERNS = TPP
        except ImportError:
            THIRD_PARTY_KEY_PATTERNS = ()
    return THIRD_PARTY_KEY_PATTERNS


# XSS reflection probe marker prefix — unique enough to avoid collision with real data


def record(url: str, **extra: Any) -> dict[str, Any]:
    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        **extra,
    }


def build_response_index(responses: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build a URL -> response lookup dict from a list of response records.

    Args:
        responses: List of HTTP response dicts with 'url' keys.

    Returns:
        Dict mapping stripped URL strings to response dicts.
    """
    return {str(r.get("url", "")).strip(): r for r in responses if r.get("url")}


def compute_severity(risk_score: int) -> str:
    """Convert a numeric risk score to a severity label.

    Args:
        risk_score: Numeric risk score.

    Returns:
        'high' if score >= 8, 'medium' if score >= 4, else 'low'.
    """
    if risk_score >= 8:
        return "high"
    if risk_score >= 4:
        return "medium"
    return "low"


def scan_urls_and_responses(
    urls: set[str],
    responses: list[dict[str, Any]],
    *,
    url_matcher: Callable[[str], bool] | None = None,
    response_matcher: Callable[[dict[str, Any]], bool] | None = None,
    url_indicator: str = "",
    response_indicator: str = "",
    limit: int = 80,
) -> list[dict[str, Any]]:
    """Scan URLs and responses for exposure indicators using a common two-phase pattern.

    This encapsulates the repeated pattern across exposure checkers:
    1. Iterate URLs, check for path hints, record matches
    2. Iterate responses, check body patterns, record matches

    Args:
        urls: Set of URLs to scan for path-based indicators.
        responses: List of HTTP response dicts to scan for body-based indicators.
        url_matcher: Callable(url: str) -> bool. If True, record the URL.
        response_matcher: Callable(response: dict) -> bool. If True, record the response.
        url_indicator: Indicator label for URL matches.
        response_indicator: Indicator label for response matches.
        limit: Maximum number of findings to return.

    Returns:
        List of findings from both URL and response scanning phases.
    """
    findings: list[dict[str, Any]] = []

    # Phase 1: URL scanning
    if url_matcher and url_indicator:
        for url in sorted(urls):
            if url_matcher(url):
                findings.append(record(url, indicator=url_indicator))

    # Phase 2: Response scanning
    if response_matcher and response_indicator:
        for response in responses:
            if response_matcher(response):
                findings.append(
                    record(
                        str(response.get("url", "")),
                        status_code=response.get("status_code"),
                        indicator=response_indicator,
                    )
                )

    return findings[:limit]


def scan_responses(
    responses: list[dict[str, Any]],
    *,
    response_matcher: Callable[[dict[str, Any]], bool] | None = None,
    response_indicator: str = "",
    limit: int = 80,
    extra_fields: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Scan responses for exposure indicators using a common pattern.

    This encapsulates the repeated pattern across response-only checkers:
    iterate responses, check body/header patterns, record matches.

    Args:
        responses: List of HTTP response dicts to scan.
        response_matcher: Callable(response: dict) -> bool. If True, record the response.
        response_indicator: Indicator label for matches.
        limit: Maximum number of findings to return.
        extra_fields: Optional extra fields to include in each finding.

    Returns:
        List of findings from response scanning, each with standard endpoint fields.
    """
    findings: list[dict[str, Any]] = []
    if not response_matcher or not response_indicator:
        return findings

    for response in responses:
        if response_matcher(response):
            url = str(response.get("url", ""))
            finding = record(
                url,
                status_code=response.get("status_code"),
                indicator=response_indicator,
            )
            if extra_fields:
                finding.update(extra_fields)
            findings.append(finding)

    return findings[:limit]
