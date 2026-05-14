"""Active HTTP probes for security testing (OPTIONS, Origin, HEAD, CORS, TRACE).

Sends targeted HTTP requests with specific methods and headers to detect
misconfigurations like unsafe methods, CORS issues, and TRACE exposure.
Each probe includes confidence scoring and severity classification.
"""

import re
from typing import Any

from src.analysis.active.brute_force.cookie_manipulation import cookie_manipulation_probe
from src.analysis.active.injection.csrf import csrf_active_probe
from src.analysis.active.injection.jwt_manipulation import jwt_manipulation_probe
from src.analysis.active.injection.parameter_pollution import hpp_active_probe
from src.analysis.active.injection.websocket_hijacking import websocket_hijacking_probe
from src.analysis.active.injection.xpath import xpath_injection_active_probe
from src.analysis.active.injection.xss_reflect_probe import xss_reflect_probe
from src.analysis.checks.active.file_upload_probe import file_upload_active_probe
from src.analysis.checks.active.idor_probe import idor_active_probe
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.helpers import (
    probe_confidence_from_map as _probe_confidence_from_map,
)
from src.analysis.helpers import (
    probe_severity_from_map as _probe_severity_from_map,
)
from src.analysis.passive.runtime import ResponseCache

__all__ = [
    "cookie_manipulation_probe",
    "cors_preflight_probe",
    "csrf_active_probe",
    "file_upload_active_probe",
    "head_method_probe",
    "hpp_active_probe",
    "http2_probe",
    "http_smuggling_probe",
    "idor_active_probe",
    "jwt_manipulation_probe",
    "oauth_flow_analyzer",
    "options_method_probe",
    "origin_reflection_probe",
    "sqli_safe_probe",
    "trace_method_probe",
    "websocket_hijacking_probe",
    "websocket_message_probe",
    "xpath_injection_active_probe",
    "xss_reflect_probe",
    "brute_force_resistance_probe",
    "race_condition_probe",
]

# HTTP method probes extracted to active_probes_http_methods.py
# Re-exported for backward compatibility
from src.analysis.active.brute_force import brute_force_resistance_probe
from src.analysis.active.http_methods import (
    _probe_confidence,
    _probe_severity,
    cors_preflight_probe,
    head_method_probe,
    options_method_probe,
    origin_reflection_probe,
    trace_method_probe,
)
from src.analysis.active.http_smuggling import (
    http2_probe,
    http_smuggling_probe,
)
from src.analysis.active.race_condition import race_condition_probe

_error_re = re.compile(
    r"(?i)(?:sql\s*syntax|mysql_fetch|pg_query|ociexecute|ora-|traceback|stack\s*trace|"
    r"exception|syntax\s*error|unexpected\s+token|unterminated|string\s+literal|"
    r"unclosed\s+quotation|invalid\s+column|invalid\s+object|invalid\s+table|"
    r"division\s+by\s+zero|out\s+of\s+range|constraint\s+violation|duplicate\s+key|"
    r"integrity\s+constraint|foreign\s+key)"
)


def sqli_safe_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 12
) -> list[dict[str, Any]]:
    """Send safe SQLi test payloads to SQL-relevant parameters and check for error responses.

    This probe sends harmless SQL test strings to parameters that look like SQL sinks
    (search, query, filter, sort, id, etc.) and analyzes responses for SQL error patterns.
    Only sends one payload per parameter and stops after first significant finding per URL.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of SQLi probe findings with detected error patterns.
    """
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

    from src.recon.common import normalize_url

    findings: list[dict[str, Any]] = []
    sql_param_names = {
        "search",
        "query",
        "filter",
        "sort",
        "order",
        "where",
        "q",
        "s",
        "id",
        "uid",
        "user_id",
        "column",
        "select",
        "sql",
        "db",
        "table",
        "expr",
        "keyword",
        "term",
        "lookup",
        "match",
    }

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        # Find SQL-relevant parameters
        sql_params = [
            (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in sql_param_names
        ]
        if not sql_params:
            continue

        endpoint_key = endpoint_signature(url)
        url_findings: list[dict[str, Any]] = []

        for idx, param_name, param_value in sql_params:
            # Test with single quote payload (most likely to trigger errors safely)
            test_value = "'"
            updated = list(query_pairs)
            updated[idx] = (param_name, test_value)
            test_url = normalize_url(
                urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
            )

            response = response_cache.request(
                test_url,
                headers={"Cache-Control": "no-cache", "X-SQLi-Probe": "1"},
            )
            if not response:
                continue

            body = str(response.get("body_text", "") or "")[:8000]
            status = int(response.get("status_code") or 0)
            match = _error_re.search(body)

            if match:
                url_findings.append(
                    {
                        "parameter": param_name,
                        "payload": test_value,
                        "payload_type": "single_quote",
                        "status_code": status,
                        "error_pattern": match.group(0),
                        "error_context": body[max(0, match.start() - 50) : match.end() + 50],
                    }
                )
                break  # Stop after first SQL error for this URL

        if url_findings:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": ["sqli_error_response"],
                    "probes": url_findings,
                    "confidence": _probe_confidence(["sqli_error_response"]),
                    "severity": _probe_severity(["sqli_error_response"]),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings


# HTTP request smuggling detection patterns


def websocket_message_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 8
) -> list[dict[str, Any]]:
    """Probe WebSocket endpoints for message injection and auth weaknesses."""
    from urllib.parse import parse_qsl, urlparse

    findings: list[dict[str, Any]] = []
    seen_endpoints: set[str] = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        parsed = urlparse(url)
        path = parsed.path.lower()

        is_ws_endpoint = (
            parsed.scheme in ("ws", "wss")
            or "/ws/" in path
            or "/socket" in path
            or "/websocket" in path
            or "/realtime" in path
            or "/live" in path
            or "/channel" in path
            or "/stream" in path
            or "/subscribe" in path
        )
        if not is_ws_endpoint:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)

        issues: list[str] = []
        ws_details: list[dict[str, Any]] = []

        query_params = dict(parse_qsl(parsed.query))
        auth_params = {"token", "auth", "key", "api_key", "access_token", "session"}
        found_auth_in_url = auth_params & set(k.lower() for k in query_params.keys())
        if found_auth_in_url:
            issues.append("ws_auth_token_in_url")
            ws_details.append({"type": "auth_in_url", "parameters": sorted(found_auth_in_url)})

        auth_indicators = {"/auth", "/login", "/oauth", "/signin"}
        has_auth_path = any(ind in path for ind in auth_indicators)
        if not has_auth_path and not found_auth_in_url:
            issues.append("ws_no_auth_required")
            ws_details.append({"type": "no_auth_indicator", "path": parsed.path})

        if "origin" in query_params:
            issues.append("ws_origin_not_validated")
            ws_details.append({"type": "origin_param", "value": query_params.get("origin", "")})

        # Check for arbitrary message acceptance (no message validation)
        if "/broadcast" in path or "/publish" in path or "/send" in path:
            issues.append("ws_arbitrary_message_acceptance")
        # Check for missing subprotocol validation
        if "/graphql" in path or "/subscriptions" in path:
            issues.append("ws_graphql_subscriptions")
            ws_details.append({"type": "graphql_subscription", "path": parsed.path})

        # Check for potential connection hijacking (upgrade without auth)
        if "/admin" in path or "/control" in path or "/manage" in path:
            issues.append("ws_admin_no_auth")
            ws_details.append({"type": "admin_endpoint_no_auth", "path": parsed.path})

        response = response_cache.get(url)
        if response:
            body = str(response.get("body_text", "")).lower()
            error_leak_indicators = [
                "internal",
                "stack trace",
                "traceback",
                "debug",
                "error:",
                "exception",
            ]
            if any(ind in body for ind in error_leak_indicators):
                issues.append("ws_error_leaks_internal_info")
                ws_details.append(
                    {
                        "type": "error_leak",
                        "indicators": [ind for ind in error_leak_indicators if ind in body],
                    }
                )

            # Check for CORS headers on WebSocket upgrade response
            headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
            if "access-control-allow-origin" in headers:
                acao = headers["access-control-allow-origin"]
                if acao == "*" or acao == "null":
                    issues.append("ws_permissive_cors")
                    ws_details.append({"type": "cors_issue", "allow_origin": acao})

            # Check for missing security headers on WebSocket response
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                issues.append("ws_missing_clickjacking_protection")
                ws_details.append(
                    {"type": "missing_security_header", "header": "X-Frame-Options/CSP"}
                )

            # Check for WebSocket upgrade without Sec-WebSocket-Protocol validation
            if "sec-websocket-accept" in headers and "sec-websocket-protocol" not in headers:
                issues.append("ws_no_subprotocol_validation")
                ws_details.append({"type": "missing_subprotocol_validation"})

        if issues:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": issues,
                    "ws_details": ws_details,
                    "confidence": _probe_confidence_from_map(issues, WS_CONFIDENCE),
                    "severity": _probe_severity_from_map(issues, WS_SEVERITY),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings


# OAuth flow analyzer confidence and severity
OAUTH_CONFIDENCE = {
    "oauth_implicit_flow": 0.82,
    "oauth_missing_pkce": 0.75,
    "oauth_open_redirect": 0.88,
    "oauth_token_in_url": 0.80,
    "oauth_missing_state": 0.72,
    "oauth_wildcard_redirect": 0.90,
}

OAUTH_SEVERITY = {
    "oauth_implicit_flow": "high",
    "oauth_missing_pkce": "medium",
    "oauth_open_redirect": "high",
    "oauth_token_in_url": "high",
    "oauth_missing_state": "medium",
    "oauth_wildcard_redirect": "critical",
}


def oauth_flow_analyzer(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 10
) -> list[dict[str, Any]]:
    """Analyze OAuth/SAML flow endpoints for misconfigurations."""
    from urllib.parse import parse_qsl, urlparse

    findings: list[dict[str, Any]] = []
    seen_endpoints: set[str] = set()
    oauth_paths = {
        "/oauth",
        "/authorize",
        "/token",
        "/callback",
        "/signin",
        "/login",
        "/auth",
        "/saml",
        "/sso",
    }

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        parsed = urlparse(url)
        path = parsed.path.lower()

        is_oauth_endpoint = any(oauth_path in path for oauth_path in oauth_paths)
        if not is_oauth_endpoint:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)

        issues: list[str] = []
        oauth_details: list[dict[str, Any]] = []
        query_params = dict(parse_qsl(parsed.query))
        query_keys_lower = {k.lower(): v for k, v in query_params.items()}

        response_type = query_keys_lower.get("response_type", "")
        if "token" in response_type.lower() and "code" not in response_type.lower():
            issues.append("oauth_implicit_flow")
            oauth_details.append({"type": "implicit_flow", "response_type": response_type})

        if "code" in response_type.lower() and "code_challenge" not in query_keys_lower:
            issues.append("oauth_missing_pkce")
            oauth_details.append(
                {"type": "missing_pkce", "note": "No code_challenge parameter found"}
            )

        redirect_uri = query_keys_lower.get(
            "redirect_uri", query_keys_lower.get("redirect_url", "")
        )
        if redirect_uri:
            redirect_parsed = urlparse(redirect_uri)
            if redirect_parsed.netloc and redirect_parsed.netloc.lower() != parsed.netloc.lower():
                issues.append("oauth_open_redirect")
                oauth_details.append({"type": "open_redirect", "redirect_uri": redirect_uri})
            if "*" in redirect_uri or "localhost" in redirect_uri.lower():
                issues.append("oauth_wildcard_redirect")
                oauth_details.append({"type": "wildcard_redirect", "redirect_uri": redirect_uri})

        token_params = {"access_token", "token", "id_token", "refresh_token"}
        found_tokens = token_params & set(query_keys_lower.keys())
        if found_tokens:
            issues.append("oauth_token_in_url")
            oauth_details.append({"type": "token_in_url", "parameters": sorted(found_tokens)})

        if "state" not in query_keys_lower and "code" in response_type.lower():
            issues.append("oauth_missing_state")
            oauth_details.append(
                {"type": "missing_state", "note": "No state parameter in authorization request"}
            )

        if issues:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": issues,
                    "oauth_details": oauth_details,
                    "confidence": _probe_confidence_from_map(issues, OAUTH_CONFIDENCE),
                    "severity": _probe_severity_from_map(issues, OAUTH_SEVERITY),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings


WS_CONFIDENCE = {
    "ws_arbitrary_message_acceptance": 0.70,
    "ws_missing_rate_limit": 0.60,
    "ws_graphql_subscriptions": 0.65,
    "ws_admin_no_auth": 0.90,
    "ws_permissive_cors": 0.75,
    "ws_missing_clickjacking_protection": 0.55,
    "ws_no_subprotocol_validation": 0.60,
}

WS_SEVERITY = {
    "ws_no_auth_required": "high",
    "ws_auth_token_in_url": "high",
    "ws_origin_not_validated": "medium",
    "ws_accepts_arbitrary_messages": "medium",
    "ws_reflects_message_content": "high",
    "ws_error_leaks_internal_info": "medium",
    "ws_arbitrary_message_acceptance": "medium",
    "ws_missing_rate_limit": "low",
    "ws_graphql_subscriptions": "medium",
    "ws_admin_no_auth": "critical",
    "ws_permissive_cors": "high",
    "ws_missing_clickjacking_protection": "low",
    "ws_no_subprotocol_validation": "low",
}
