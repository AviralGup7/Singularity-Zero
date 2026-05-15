"""Anomaly detector for identifying unusual URLs and response patterns.

Scans URLs for suspicious characteristics like encoded characters, random
path segments, backup file paths, and unusual parameter combinations. Also
analyzes response bodies for server errors and stack traces.

Provides weighted scoring based on exploitability potential and correlation
analysis between multiple anomaly signals to surface high-risk findings.
"""

import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    is_auth_flow_endpoint,
    is_noise_url,
    meaningful_query_pairs,
)
from src.analysis.passive.runtime import looks_random

_ADMIN_PATH_PATTERNS = re.compile(
    r"(?i)/(admin|manage|console|control|panel|wp-admin|phpmyadmin)(?:/|$)"
)
_ADMIN_PATH_SOFT = re.compile(r"(?i)/(dashboard|admin-panel|management)(?:/|$)")
_DEBUG_PATH_PATTERNS = re.compile(r"(?i)/(debug|trace|profiler|actuator)(?:/|$)")
_DEBUG_PATH_SOFT = re.compile(r"(?i)/(swagger|api-docs|openapi|graphql)(?:/|$)")
_SENSITIVE_FILE_PATTERNS = re.compile(
    r"(?i)\.(env|config|ini|conf|properties|yml|yaml|xml|log)(?:$|\?)"
)
_VERSION_INFO_PATTERNS = re.compile(r"(?i)/(v[0-9]+|version|release|build)(?:/|$)")
_KNOWN_LEGITIMATE_PATHS = {
    "/dashboard",
    "/api-docs",
    "/swagger",
    "/swagger-ui",
    "/graphql",
    "/openapi",
    "/docs",
    "/api/v1",
    "/api/v2",
    "/api/v3",
}

# Signal weights based on exploitability potential
# Higher weights indicate signals that are more likely to lead to actionable findings
SIGNAL_EXPLOITABILITY_WEIGHTS: dict[str, float] = {
    # High exploitability - direct attack vectors
    "api_key_in_url": 0.9,
    "sqli_surface_path": 0.8,
    "sqli_surface_param": 0.8,
    "sqli_order_injection_surface": 0.85,
    "ssrf_adjacent_path": 0.75,
    "graphql_introspection_attempt": 0.8,
    "debug_mode_enabled": 0.85,
    "connection_string_leak": 0.95,
    "credential_leak_in_error": 0.95,
    "internal_ip_leakage": 0.7,
    "internal_infrastructure_leak": 0.75,
    # Medium exploitability - reconnaissance value
    "admin_panel_path": 0.6,
    "admin_like_path": 0.4,
    "debug_interface_path": 0.65,
    "debug_like_path": 0.45,
    "sensitive_file_extension": 0.7,
    "backup_like_path": 0.65,
    "random_like_path_segment": 0.5,
    "encoded_characters": 0.3,
    "multi_dot_path": 0.35,
    "version_info_path": 0.3,
    "unusual_parameter_combo": 0.5,
    "auth_redirect_token_overlap": 0.6,
    "graphql_mutation_or_batch": 0.55,
    "ws_no_auth_path": 0.65,
    "ws_auth_in_url": 0.5,
    "ws_origin_param": 0.45,
    "websocket_endpoint": 0.35,
    "rate_limit_endpoint": 0.3,
    "payment_surface_anomaly": 0.55,
    "ai_inference_endpoint": 0.5,
    "server_error_response": 0.6,
    "stack_trace_keyword": 0.75,
    "sql_error_keyword": 0.85,
    "php_warning_keyword": 0.5,
    "java_stack_trace": 0.75,
    "nodejs_error": 0.65,
    "python_stack_trace": 0.75,
    "dotnet_error": 0.7,
    "graphql_error_leak": 0.6,
}

# Correlated signal pairs that indicate higher risk when found together
HIGH_RISK_SIGNAL_CORRELATIONS: dict[tuple[str, str], float] = {
    ("admin_panel_path", "debug_interface_path"): 0.15,
    ("admin_panel_path", "sensitive_file_extension"): 0.12,
    ("sqli_surface_path", "sqli_surface_param"): 0.1,
    ("sqli_surface_path", "server_error_response"): 0.15,
    ("ssrf_adjacent_path", "encoded_characters"): 0.1,
    ("debug_mode_enabled", "stack_trace_keyword"): 0.15,
    ("debug_mode_enabled", "internal_ip_leakage"): 0.12,
    ("api_key_in_url", "credential_leak_in_error"): 0.2,
    ("connection_string_leak", "server_error_response"): 0.15,
    ("graphql_introspection_attempt", "graphql_error_leak"): 0.1,
    ("ws_no_auth_path", "ws_auth_in_url"): 0.1,
    ("backup_like_path", "sensitive_file_extension"): 0.1,
    ("random_like_path_segment", "encoded_characters"): 0.08,
    ("payment_surface_anomaly", "server_error_response"): 0.1,
    ("ai_inference_endpoint", "debug_mode_enabled"): 0.12,
}


def anomaly_detector(urls: set[str], responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect anomalous URLs and responses that deviate from normal patterns.

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts to analyze.

    Returns:
        List of anomaly findings with URL, signals, and score.
    """
    findings: list[dict[str, Any]] = []
    seen_patterns: set[str] = set()
    for raw_url in sorted(urls):
        if is_noise_url(raw_url):
            continue
        pattern_key = endpoint_signature(raw_url)
        if pattern_key in seen_patterns:
            continue
        seen_patterns.add(pattern_key)
        path = urlparse(raw_url).path or ""
        signals = []
        if "%" in raw_url:
            signals.append("encoded_characters")
        if any(
            len(segment) >= 28 and looks_random(segment) for segment in path.split("/") if segment
        ):
            signals.append("random_like_path_segment")
        if re.search(r"\.(bak|old|orig|backup|tmp|swp)(?:$|\?)", path, re.IGNORECASE):
            signals.append("backup_like_path")
        if path.count(".") >= 2:
            signals.append("multi_dot_path")
        if _ADMIN_PATH_PATTERNS.search(path):
            signals.append("admin_panel_path")
        elif _ADMIN_PATH_SOFT.search(path) and path.lower() not in _KNOWN_LEGITIMATE_PATHS:
            signals.append("admin_like_path")
        if _DEBUG_PATH_PATTERNS.search(path):
            signals.append("debug_interface_path")
        elif _DEBUG_PATH_SOFT.search(path) and path.lower() not in _KNOWN_LEGITIMATE_PATHS:
            signals.append("debug_like_path")
        if _SENSITIVE_FILE_PATTERNS.search(path):
            signals.append("sensitive_file_extension")
        if _VERSION_INFO_PATTERNS.search(path):
            signals.append("version_info_path")
        query_keys = sorted({key for key, _ in meaningful_query_pairs(raw_url)})
        families = {
            "idor": any("id" == key or key.endswith("_id") for key in query_keys),
            "redirect": any(
                key in {"next", "redirect", "return", "return_to", "state", "url"}
                for key in query_keys
            ),
            "token": any("token" in key or key in {"auth", "session"} for key in query_keys),
        }
        if sum(1 for enabled in families.values() if enabled) >= 2:
            signals.append("unusual_parameter_combo")
        if is_auth_flow_endpoint(raw_url) and families["redirect"] and families["token"]:
            signals.append("auth_redirect_token_overlap")

        # GraphQL-specific anomaly detection
        if "/graphql" in path.lower():
            query_lower = raw_url.lower()
            if any(kw in query_lower for kw in ("__schema", "__type", "introspection")):
                signals.append("graphql_introspection_attempt")
            elif any(kw in query_lower for kw in ("mutation", "batch", "alias")):
                signals.append("graphql_mutation_or_batch")

        # API key / secret pattern scanning in URLs
        api_key_params = {
            "key",
            "api_key",
            "apikey",
            "secret",
            "access_key",
            "api_secret",
            "client_secret",
        }
        if api_key_params & set(query_keys):
            signals.append("api_key_in_url")

        # WebSocket endpoint detection
        parsed_url = urlparse(raw_url)
        if (
            parsed_url.scheme in ("ws", "wss")
            or "/ws/" in path.lower()
            or "/socket" in path.lower()
            or "/socket.io" in path.lower()
        ):
            signals.append("websocket_endpoint")
            # Check for WebSocket-specific security indicators
            if (
                "/ws/" in path.lower()
                and "/auth" not in path.lower()
                and "/login" not in path.lower()
            ):
                signals.append("ws_no_auth_path")
            if any(key in query_keys for key in ("token", "auth", "session", "jwt", "key")):
                signals.append("ws_auth_in_url")
            if any(key in query_keys for key in ("origin", "referer")):
                signals.append("ws_origin_param")

        # Rate-limit / throttling endpoint detection
        if any(
            kw in path.lower()
            for kw in ("/rate-limit", "/throttle", "/quota", "/rate_limit", "/ratelimit")
        ):
            signals.append("rate_limit_endpoint")

        # Server-Side Request Forgery adjacent patterns
        if any(
            kw in path.lower() for kw in ("/proxy", "/fetch", "/import", "/webhook", "/callback")
        ):
            signals.append("ssrf_adjacent_path")

        # Payment/financial endpoint anomaly
        if any(
            kw in path.lower()
            for kw in ("/payment", "/checkout", "/billing", "/subscription", "/refund", "/invoice")
        ):
            signals.append("payment_surface_anomaly")

        # AI/ML endpoint detection
        if any(
            kw in path.lower()
            for kw in (
                "/ai/",
                "/ml/",
                "/model",
                "/predict",
                "/inference",
                "/embeddings",
                "/completion",
            )
        ):
            signals.append("ai_inference_endpoint")

        # SQL injection surface detection
        sql_path_patterns = (
            "/query",
            "/report",
            "/search",
            "/filter",
            "/export",
            "/sql",
            "/db",
            "/database",
        )
        sql_param_names = {
            "q",
            "s",
            "search",
            "query",
            "filter",
            "sort",
            "order",
            "where",
            "column",
            "select",
            "sql",
            "db",
            "table",
            "expr",
            "expression",
            "condition",
            "criteria",
            "lookup",
            "match",
            "keyword",
            "term",
        }
        if any(kw in path.lower() for kw in sql_path_patterns):
            signals.append("sqli_surface_path")
        if sql_param_names & set(query_keys):
            signals.append("sqli_surface_param")
        # Detect ORDER BY / GROUP BY style parameters (common SQLi vectors)
        if any(
            key in {"order_by", "group_by", "having", "sort_by", "orderby", "groupby"}
            for key in query_keys
        ):
            signals.append("sqli_order_injection_surface")

        if signals:
            # Calculate weighted score based on exploitability potential
            weighted_score = sum(SIGNAL_EXPLOITABILITY_WEIGHTS.get(sig, 0.4) for sig in signals)

            # Add correlation bonus for high-risk signal pairs (capped at 0.5 to prevent overflow)
            correlation_bonus = 0.0
            correlated_pairs = []
            signal_set = set(signals)
            for (sig1, sig2), bonus in HIGH_RISK_SIGNAL_CORRELATIONS.items():
                if sig1 in signal_set and sig2 in signal_set:
                    correlation_bonus += bonus
                    correlated_pairs.append(f"{sig1}+{sig2}")
            correlation_bonus = min(correlation_bonus, 0.5)  # Cap correlation bonus

            # Determine severity based on weighted score and correlation
            total_score = weighted_score + correlation_bonus
            if total_score >= 1.5:
                severity = "high"
            elif total_score >= 0.8:
                severity = "medium"
            else:
                severity = "low"

            findings.append(
                {
                    "url": raw_url,
                    "endpoint_key": pattern_key,
                    "endpoint_type": classify_endpoint(raw_url),
                    "score": len(signals),
                    "weighted_score": round(total_score, 3),
                    "severity": severity,
                    "signals": signals,
                    "correlated_pairs": correlated_pairs,
                    "correlation_bonus": round(correlation_bonus, 3),
                    "explanation": _build_anomaly_explanation(
                        signals, correlated_pairs, total_score
                    ),
                }
            )

    seen_response_keys: set[str] = set()
    for response in responses:
        resp_url = str(response.get("url", ""))
        if is_noise_url(resp_url):
            continue
        resp_sig = endpoint_signature(resp_url)
        if resp_sig in seen_response_keys:
            continue
        seen_response_keys.add(resp_sig)
        body = response.get("body_text", "")
        response_signals = []
        status_code = int(response.get("status_code") or 0)
        if status_code >= 500:
            response_signals.append("server_error_response")
        if any(
            token in body.lower()
            for token in ["traceback", "stack trace", "exception", "nullreferenceexception"]
        ):
            response_signals.append("stack_trace_keyword")
        if any(
            token in body.lower()
            for token in ["sql syntax", "mysql_fetch", "pg_query", "ociexecute", "ora-"]
        ):
            response_signals.append("sql_error_keyword")
        if any(
            token in body.lower()
            for token in ["warning:", "deprecated", "notice:", "strict standards"]
        ):
            response_signals.append("php_warning_keyword")

        # Enhanced error pattern detection
        body_lower = body.lower()
        # Java/Spring errors
        if any(
            token in body_lower
            for token in [
                "org.springframework",
                "java.lang.",
                "nested exception",
                "whitelabel error",
            ]
        ):
            response_signals.append("java_stack_trace")
        # Node.js/Express errors
        if any(
            token in body_lower
            for token in ["error: cannot", "unhandled rejection", "typeerror:", "referenceerror:"]
        ):
            response_signals.append("nodejs_error")
        # Python/Flask/Django errors
        if any(
            token in body_lower
            for token in ["traceback (most recent", "django.core.exceptions", "flask.debug"]
        ):
            response_signals.append("python_stack_trace")
        # .NET errors
        if any(
            token in body_lower
            for token in [
                "system.invalidoperationexception",
                "system.nullreferenceexception",
                "yellow screen of death",
            ]
        ):
            response_signals.append("dotnet_error")
        # GraphQL errors
        if (
            any(token in body_lower for token in ['"errors":', '"message":', '"locations":'])
            and "graphql" in body_lower
        ):
            response_signals.append("graphql_error_leak")
        # Debug/verbose mode indicators
        if any(
            token in body_lower
            for token in ["debug=true", "debug mode", "development server", "werkzeug"]
        ):
            response_signals.append("debug_mode_enabled")
        # Internal IP/host leakage in error responses
        if status_code >= 400:
            if re.search(
                r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168\.)\d{1,3}\.\d{1,3}", body
            ):
                response_signals.append("internal_ip_leakage")
            if re.search(
                r"(?i)(?:internal[-_]?server|backend|upstream|origin)\s*(?:error|timeout|refused)",
                body,
            ):
                response_signals.append("internal_infrastructure_leak")
        # Information disclosure in error messages
        if any(
            token in body_lower
            for token in [
                "database connection",
                "connection string",
                "mongodb://",
                "postgresql://",
                "mysql://",
            ]
        ):
            response_signals.append("connection_string_leak")
        if (
            any(
                token in body_lower
                for token in ["api_key", "api_secret", "secret_key", "access_key"]
            )
            and status_code >= 400
        ):
            response_signals.append("credential_leak_in_error")

        if response_signals:
            # Calculate weighted score based on exploitability potential
            weighted_score = sum(
                SIGNAL_EXPLOITABILITY_WEIGHTS.get(sig, 0.4) for sig in response_signals
            )

            # Add correlation bonus for high-risk signal pairs (capped at 0.5 to prevent overflow)
            correlation_bonus = 0.0
            correlated_pairs = []
            signal_set = set(response_signals)
            for (sig1, sig2), bonus in HIGH_RISK_SIGNAL_CORRELATIONS.items():
                if sig1 in signal_set and sig2 in signal_set:
                    correlation_bonus += bonus
                    correlated_pairs.append(f"{sig1}+{sig2}")
            correlation_bonus = min(correlation_bonus, 0.5)  # Cap correlation bonus

            # Determine severity based on weighted score and correlation
            total_score = weighted_score + correlation_bonus
            if total_score >= 1.5:
                severity = "high"
            elif total_score >= 0.8:
                severity = "medium"
            else:
                severity = "low"

            findings.append(
                {
                    "url": response.get("url", ""),
                    "endpoint_key": endpoint_signature(response.get("url", "")),
                    "endpoint_type": classify_endpoint(response.get("url", "")),
                    "score": len(response_signals) + 1,
                    "weighted_score": round(total_score, 3),
                    "severity": severity,
                    "signals": response_signals,
                    "status_code": status_code,
                    "correlated_pairs": correlated_pairs,
                    "correlation_bonus": round(correlation_bonus, 3),
                    "explanation": _build_anomaly_explanation(
                        response_signals, correlated_pairs, total_score
                    ),
                }
            )

    findings.sort(key=lambda item: (-item["weighted_score"], -item["score"], item["url"]))
    return findings[:120]


def _build_anomaly_explanation(
    signals: list[str], correlated_pairs: list[str], total_score: float
) -> str:
    """Build a human-readable explanation for an anomaly finding.

    Args:
        signals: List of detected anomaly signals.
        correlated_pairs: List of correlated signal pairs found.
        total_score: Combined weighted score with correlation bonus.

    Returns:
        Human-readable explanation string.
    """
    parts: list[str] = []

    # Group signals by category for clearer explanation
    high_risk_signals = [s for s in signals if SIGNAL_EXPLOITABILITY_WEIGHTS.get(s, 0.4) >= 0.7]
    medium_risk_signals = [
        s for s in signals if 0.4 <= SIGNAL_EXPLOITABILITY_WEIGHTS.get(s, 0.4) < 0.7
    ]
    low_risk_signals = [s for s in signals if SIGNAL_EXPLOITABILITY_WEIGHTS.get(s, 0.4) < 0.4]

    if high_risk_signals:
        parts.append(f"High-risk indicators: {', '.join(high_risk_signals[:4])}.")
    if medium_risk_signals:
        parts.append(f"Medium-risk indicators: {', '.join(medium_risk_signals[:4])}.")
    if low_risk_signals:
        parts.append(f"Low-risk indicators: {', '.join(low_risk_signals[:4])}.")

    if correlated_pairs:
        parts.append(
            f"Correlated signal pairs ({', '.join(correlated_pairs[:3])}) increase exploitability confidence."
        )

    if total_score >= 1.5:
        parts.append("Overall anomaly score indicates a high-priority target for manual review.")
    elif total_score >= 0.8:
        parts.append("Overall anomaly score suggests moderate risk worth investigating.")
    else:
        parts.append("Overall anomaly score is low but may warrant attention in context.")

    return (
        " ".join(parts) if parts else f"Anomalous pattern detected with {len(signals)} signal(s)."
    )
