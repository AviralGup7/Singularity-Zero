"""Active HTTP probes for security testing (OPTIONS, Origin, HEAD, CORS, TRACE).

Sends targeted HTTP requests with specific methods and headers to detect
misconfigurations like unsafe methods, CORS issues, and TRACE exposure.
Each probe includes confidence scoring and severity classification.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    from src.analysis.active.auth_bypass.analyzer import run_auth_bypass_probes
    from src.analysis.active.brute_force import brute_force_resistance_probe
    from src.analysis.active.brute_force.cookie_manipulation import cookie_manipulation_probe
    from src.analysis.active.cloud_metadata import cloud_metadata_active_probe
    from src.analysis.active.auth.credential_vault import CredentialVault
    from src.analysis.active.graphql import graphql_active_probe
    from src.analysis.active.graphql_ws_probe import graphql_ws_injection_probe
    from src.analysis.active.http_methods import (
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
    from src.analysis.active.injection.command_injection import command_injection_active_probe
    from src.analysis.active.injection.crlf.crlf_probe import crlf_injection_probe
    from src.analysis.active.injection.csrf import csrf_active_probe
    from src.analysis.active.injection.deserialization import deserialization_probe
    from src.analysis.active.injection.jwt_manipulation import jwt_manipulation_probe
    from src.analysis.active.injection.ldap import ldap_injection_active_probe
    from src.analysis.active.injection.nosql import nosql_injection_probe
    from src.analysis.active.injection.open_redirect import open_redirect_active_probe
    from src.analysis.active.injection.parameter_pollution import hpp_active_probe
    from src.analysis.active.injection.path_traversal import path_traversal_active_probe
    from src.analysis.active.injection.proxy_ssrf import proxy_ssrf_probe
    from src.analysis.active.injection.sqli import sqli_safe_probe
    from src.analysis.active.injection.ssrf import ssrf_active_probe
    from src.analysis.active.injection.ssti import ssti_active_probe
    from src.analysis.active.injection.websocket_hijacking import websocket_hijacking_probe
    from src.analysis.active.injection.xpath import xpath_injection_active_probe
    from src.analysis.active.injection.xss_reflect_probe import xss_reflect_probe
    from src.analysis.active.injection.xxe import xxe_active_probe
    from src.analysis.active.jwt_attacks import run_jwt_attack_suite
    from src.analysis.active.param_mining import param_mining_probe
    from src.analysis.active.race_condition import race_condition_probe
    from src.analysis.checks.active.file_upload_probe import file_upload_active_probe
    from src.analysis.checks.active.idor_probe import idor_active_probe
    from src.analysis.helpers import (
        classify_endpoint,
        endpoint_base_key,
        endpoint_signature,
        probe_confidence_from_map,
        probe_severity_from_map,
    )
    from src.analysis.passive.runtime import ResponseCache
    from src.detection.ast import analyze_html_for_prototype_pollution
except ImportError as exc:
    logger.warning("Some active probe modules failed to import: %s", exc)

__all__ = [
    "brute_force_resistance_probe",
    "cloud_metadata_active_probe",
    "command_injection_active_probe",
    "cookie_manipulation_probe",
    "cors_preflight_probe",
    "crlf_injection_probe",
    "csrf_active_probe",
    "deserialization_probe",
    "file_upload_active_probe",
    "graphql_active_probe",
    "graphql_ws_injection_probe",
    "head_method_probe",
    "hpp_active_probe",
    "http2_probe",
    "http_smuggling_probe",
    "idor_active_probe",
    "jwt_manipulation_probe",
    "ldap_injection_active_probe",
    "nosql_injection_probe",
    "oauth_flow_analyzer",
    "open_redirect_active_probe",
    "options_method_probe",
    "origin_reflection_probe",
    "param_mining_probe",
    "path_traversal_active_probe",
    "proxy_ssrf_probe",
    "race_condition_probe",
    "run_auth_bypass_probes",
    "run_jwt_attack_suite",
    "run_saml_attack_suite",
    "sqli_safe_probe",
    "ssrf_active_probe",
    "ssti_active_probe",
    "trace_method_probe",
    "websocket_hijacking_probe",
    "websocket_message_probe",
    "xpath_injection_active_probe",
    "xss_reflect_probe",
    "xxe_active_probe",
]


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

        if "/broadcast" in path or "/publish" in path or "/send" in path:
            issues.append("ws_arbitrary_message_acceptance")
        if "/graphql" in path or "/subscriptions" in path:
            issues.append("ws_graphql_subscriptions")
            ws_details.append({"type": "graphql_subscription", "path": parsed.path})

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

            headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
            if "access-control-allow-origin" in headers:
                acao = headers["access-control-allow-origin"]
                if acao == "*" or acao == "null":
                    issues.append("ws_permissive_cors")
                    ws_details.append({"type": "cors_issue", "allow_origin": acao})

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
                    "confidence": probe_confidence_from_map(issues, WS_CONFIDENCE),
                    "severity": probe_severity_from_map(issues, WS_SEVERITY),
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

        response = response_cache.get(url)
        combined_params = dict(query_params)
        if response and "request_body" in response:
            try:
                body = str(response["request_body"])
                combined_params.update(dict(parse_qsl(body)))
            except Exception as exc:  # noqa: S110
                import logging
                logging.getLogger(__name__).debug(
                    "oauth_flow_analyzer: failed to parse request body for %s: %s", url, exc
                )

        query_keys_lower = {k.lower(): v for k, v in combined_params.items()}

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
                    "confidence": probe_confidence_from_map(issues, OAUTH_CONFIDENCE),
                    "severity": probe_severity_from_map(issues, OAUTH_SEVERITY),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings


WS_CONFIDENCE = {
    "ws_arbitrary_message_acceptance": 0.70,
    "ws_auth_token_in_url": 0.75,
    "ws_no_auth_required": 0.82,
    "ws_missing_rate_limit": 0.60,
    "ws_graphql_subscriptions": 0.65,
    "ws_admin_no_auth": 0.90,
    "ws_permissive_cors": 0.75,
    "ws_missing_clickjacking_protection": 0.55,
    "ws_no_subprotocol_validation": 0.60,
    "ws_error_leaks_internal_info": 0.65,
    "ws_origin_not_validated": 0.72,
    "graphql_ws_subscription_data_leaked": 0.90,
    "graphql_ws_unauthenticated_subscription": 0.78,
    "graphql_ws_csws_origin_bypass": 0.80,
}

WS_SEVERITY = {
    "ws_no_auth_required": "high",
    "ws_auth_token_in_url": "high",
    "ws_origin_not_validated": "medium",
    "ws_accepts_arbitrary_messages": "medium",
    "ws_arbitrary_message_acceptance": "medium",
    "ws_reflects_message_content": "high",
    "ws_error_leaks_internal_info": "medium",
    "ws_missing_rate_limit": "low",
    "ws_graphql_subscriptions": "medium",
    "ws_admin_no_auth": "critical",
    "ws_permissive_cors": "high",
    "ws_missing_clickjacking_protection": "low",
    "ws_no_subprotocol_validation": "low",
    "graphql_ws_subscription_data_leaked": "critical",
    "graphql_ws_unauthenticated_subscription": "high",
    "graphql_ws_csws_origin_bypass": "high",
}


def run_saml_attack_suite(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    credential_vault: CredentialVault,
    config: dict[str, Any] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Orchestrate SAML active attack probes when SAML assertions are captured."""
    config = config or {}
    limit = int(config.get("saml_limit", 12))
    from src.analysis.active.saml_attacks import (
        run_assertion_replay,
        run_signature_strip,
        run_xsw_attack,
    )

    saml_replay_results = run_assertion_replay(priority_urls, response_cache, credential_vault, limit=limit)
    xsw_results = run_xsw_attack(priority_urls, response_cache, credential_vault, limit=limit)
    strip_results = run_signature_strip(priority_urls, response_cache, credential_vault, limit=limit)
    return {
        "saml_assertion_replay": saml_replay_results,
        "saml_xsw_attack": xsw_results,
        "saml_signature_strip": strip_results,
    }


def run_prototype_pollution_walker(
    priority_items: list[dict[str, Any]],
    response_cache: Any | None = None,
    *,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Walk HTML/JSON responses for prototype pollution candidates."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in priority_items:
        if len(findings) >= limit:
            break
        url = str(item.get("url", "")) if isinstance(item, dict) else str(item)
        url = url.strip()
        if not url or url in seen:
            continue
        seen.add(url)

        body: str | None = None
        if response_cache is not None:
            cached = response_cache.get(url)
            if cached:
                body = str(cached.get("body_text", "") or cached.get("body", "") or "")

        if not body:
            continue

        try:
            pp_findings = analyze_html_for_prototype_pollution(body, url=url)
        except Exception as exc:
            logger.debug(
                "prototype_pollution_walker failed for %s: %s", url, exc
            )
            continue

        for f in pp_findings:
            f.setdefault("probe", "prototype_pollution_walker")
            findings.append(f)

    return findings
