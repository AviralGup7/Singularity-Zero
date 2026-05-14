import re
from typing import Any

from src.analysis.analyzer_results import build_analyzer_result
from src.analysis.helpers import classify_endpoint, meaningful_query_pairs, normalize_headers
from src.analysis.passive.patterns import SENSITIVE_PATTERNS, TECH_SIGNATURES
from src.analysis.passive.runtime import ResponseCache, json_headers, redacted_snippet
from src.core.contracts.pipeline import dedup_key
from src.recon.common import normalize_url


def sensitive_data_scanner(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for response in responses:
        body = response.get("body_text") or ""
        if not body:
            continue
        for label, pattern in SENSITIVE_PATTERNS:
            for match in pattern.finditer(body):
                matched = match.group(0)
                dedupe_signature = dedup_key(response["url"], label, matched[:40])
                if dedupe_signature in seen:
                    continue
                seen.add(dedupe_signature)
                findings.append(
                    build_analyzer_result(
                        response["url"],
                        response=response,
                        include_endpoint_keys=False,
                        indicator=label,
                        snippet=redacted_snippet(body, match.start(), match.end()),
                    )
                )
                if len(findings) >= 100:
                    return findings
    return findings


def header_checker(
    targets: list[str], response_cache: ResponseCache, response_map: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for target in targets:
        response = response_map.get(normalize_url(target)) or response_cache.get(target)
        if not response:
            continue
        headers = {key.lower(): value for key, value in (response.get("headers") or {}).items()}
        issues = []

        if response["url"].startswith("https://") and "strict-transport-security" not in headers:
            issues.append("missing_hsts")
        elif "strict-transport-security" in headers:
            hsts_value = headers["strict-transport-security"].lower()
            if "includesubdomains" not in hsts_value:
                issues.append("hsts_missing_includesubdomains")
            if "preload" not in hsts_value:
                issues.append("hsts_missing_preload")
        if "content-security-policy" not in headers:
            issues.append("missing_content_security_policy")
        else:
            csp_value = headers["content-security-policy"].lower()
            if "unsafe-inline" in csp_value:
                issues.append("csp_unsafe_inline")
            if "unsafe-eval" in csp_value:
                issues.append("csp_unsafe_eval")
            if "default-src" not in csp_value and "script-src" not in csp_value:
                issues.append("csp_missing_directives")
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            issues.append("missing_x_content_type_options")
        has_clickjacking_protection = "x-frame-options" in headers or (
            "content-security-policy" in headers
            and "frame-ancestors" in headers["content-security-policy"].lower()
        )
        if not has_clickjacking_protection:
            issues.append("missing_clickjacking_protection")
        elif "x-frame-options" in headers and headers["x-frame-options"].lower() not in {
            "deny",
            "sameorigin",
        }:
            issues.append("weak_x_frame_options")
        if "referrer-policy" not in headers:
            issues.append("missing_referrer_policy")
        elif headers["referrer-policy"].lower() not in {
            "no-referrer",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        }:
            issues.append("weak_referrer_policy")
        if "permissions-policy" not in headers:
            issues.append("missing_permissions_policy")
        # Check for server version disclosure
        server_header = headers.get("server", "")
        if server_header and any(
            v in server_header.lower() for v in ("apache/", "nginx/", "iis/", "php/")
        ):
            issues.append("server_version_disclosure")
        # Check for X-Powered-By disclosure
        if "x-powered-by" in headers:
            issues.append("x_powered_by_disclosure")
        # Check for cache control on sensitive endpoints
        url_lower = response.get("url", "").lower()
        if any(
            token in url_lower
            for token in ("/api/", "/auth", "/login", "/admin", "/profile", "/account")
        ):
            cache_control = headers.get("cache-control", "").lower()
            pragma = headers.get("pragma", "").lower()
            if (
                not any(token in cache_control for token in ("no-store", "private", "no-cache"))
                and "no-cache" not in pragma
            ):
                issues.append("missing_cache_control_sensitive")

        if issues:
            findings.append(
                build_analyzer_result(
                    response["url"], response=response, include_endpoint_keys=False, issues=issues
                )
            )
    return findings


def cookie_security_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for response in responses:
        headers = response.get("headers") or {}
        raw_cookie_headers: list[str] = []
        for key, value in headers.items():
            if str(key).lower() != "set-cookie":
                continue
            if isinstance(value, list):
                raw_cookie_headers.extend(str(item) for item in value if item)
            else:
                raw_cookie_headers.extend(
                    part.strip() for part in str(value).split("\n") if part.strip()
                )
        issues: list[str] = []
        cookie_names: list[str] = []
        for cookie in raw_cookie_headers:
            name = cookie.split("=", 1)[0].strip() or "cookie"
            cookie_names.append(name)
            lowered = cookie.lower()
            if "secure" not in lowered:
                issues.append(f"missing_secure:{name}")
            if "httponly" not in lowered:
                issues.append(f"missing_httponly:{name}")
            if "samesite=" not in lowered:
                issues.append(f"missing_samesite:{name}")
            if "samesite=none" in lowered and "secure" not in lowered:
                issues.append(f"samesite_none_without_secure:{name}")
            # Detect overly permissive SameSite=None without Secure
            if (
                "samesite=lax" not in lowered
                and "samesite=strict" not in lowered
                and "samesite=none" not in lowered
            ):
                # Check if it's a session/auth cookie that should have stricter settings
                if any(
                    token in name.lower()
                    for token in ("session", "auth", "token", "jwt", "sid", "csrf")
                ):
                    issues.append(f"session_cookie_weak_samesite:{name}")
            # Detect cookies without expiration (persistent session cookies)
            if "expires=" not in lowered and "max-age=" not in lowered:
                if any(
                    token in name.lower() for token in ("session", "auth", "token", "jwt", "sid")
                ):
                    issues.append(f"session_cookie_no_expiration:{name}")
            # Detect cookies sent over HTTP (non-HTTPS)
            url = str(response.get("url", "")).lower()
            if (
                url.startswith("http://")
                and not url.startswith("http://localhost")
                and not url.startswith("http://127.0.0.1")
            ):
                issues.append(f"cookie_over_http:{name}")
        if issues:
            findings.append(
                build_analyzer_result(
                    response.get("url", ""),
                    response=response,
                    cookie_names=cookie_names[:12],
                    issues=sorted(set(issues)),
                )
            )
    return findings


def cors_misconfig_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for response in responses:
        headers = normalize_headers(response)
        acao = headers.get("access-control-allow-origin", "").strip()
        acac = headers.get("access-control-allow-credentials", "").strip().lower()
        acam = headers.get("access-control-allow-methods", "").strip()
        acah = headers.get("access-control-allow-headers", "").strip()
        acex = headers.get("access-control-expose-headers", "").strip()
        if not acao:
            continue
        issues = []
        severity = "medium"
        if acao == "*" and acac == "true":
            issues.append("wildcard_origin_with_credentials")
            severity = "high"
        if acao == "null":
            issues.append("null_origin_allowed")
            severity = "high"
        # Detect reflection-based CORS misconfiguration
        request_origin = headers.get("origin", "")
        if request_origin and acao == request_origin and acac == "true":
            issues.append("origin_reflection_with_credentials")
            severity = "high"
        # Detect wildcard subdomain CORS (e.g., *.example.com)
        if acao.startswith("https://") and acao.endswith(".*") or acao.startswith("https://*."):
            issues.append("wildcard_subdomain_cors")
            severity = "high"
        # Detect overly permissive methods
        if acam and ("*" in acam or "DELETE" in acam.upper() or "PUT" in acam.upper()):
            issues.append("permissive_cors_methods")
            if severity == "medium":
                severity = "medium"
        # Detect overly permissive headers
        if acah and "*" in acah:
            issues.append("wildcard_cors_headers")
            if severity == "medium":
                severity = "medium"
        # Detect sensitive header exposure
        if acex:
            sensitive_exposed = {
                "authorization",
                "x-api-key",
                "x-auth-token",
                "cookie",
                "set-cookie",
            } & set(h.lower().strip() for h in acex.split(","))
            if sensitive_exposed:
                issues.append(f"sensitive_headers_exposed:{','.join(sensitive_exposed)}")
                if severity == "medium":
                    severity = "high"
        # Detect missing Vary header (cache poisoning risk)
        if headers.get("vary", "").lower().find("origin") == -1 and acao not in {"*", ""}:
            issues.append("origin_allowlist_without_vary")
        # Detect prefix-based origin bypass (e.g., https://example.com.evil.com)
        if request_origin and acao.startswith(request_origin) and acao != request_origin:
            issues.append("origin_prefix_bypass")
            severity = "high"
        # Detect suffix-based origin bypass (e.g., https://evil-example.com)
        if (
            request_origin
            and acao.endswith(request_origin.replace("https://", ""))
            and acao != request_origin
        ):
            issues.append("origin_suffix_bypass")
            severity = "high"
        if issues:
            findings.append(
                build_analyzer_result(
                    response.get("url", ""),
                    response=response,
                    allow_origin=acao,
                    allow_credentials=acac == "true",
                    allow_methods=acam,
                    allow_headers=acah,
                    expose_headers=acex,
                    issues=issues,
                    severity=severity,
                )
            )
    return findings


def cache_control_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    sensitive_tokens = ("auth", "login", "session", "token", "account", "profile", "me")
    for response in responses:
        url = str(response.get("url", ""))
        headers = normalize_headers(response)
        cache_control = headers.get("cache-control", "").lower()
        pragma = headers.get("pragma", "").lower()
        endpoint_type = classify_endpoint(url)
        if endpoint_type not in {"AUTH", "API"} and not any(
            token in url.lower() for token in sensitive_tokens
        ):
            continue
        issues = []
        if not cache_control:
            issues.append("missing_cache_control")
        elif not any(token in cache_control for token in ("no-store", "private", "no-cache")):
            issues.append("cache_control_allows_storage")
        if "no-cache" not in pragma and not cache_control:
            issues.append("missing_pragma_no_cache")
        if issues:
            findings.append(
                build_analyzer_result(
                    url,
                    response=response,
                    cache_control=headers.get("cache-control", ""),
                    pragma=headers.get("pragma", ""),
                    issues=issues,
                )
            )
    return findings


def jsonp_endpoint_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    jsonp_re = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$]{0,48})\s*\(", re.IGNORECASE)
    for response in responses:
        url = str(response.get("url", ""))
        body = response.get("body_text") or ""
        content_type = str(response.get("content_type", "")).lower()
        params = meaningful_query_pairs(url)
        callback_param = next(
            (
                value
                for key, value in params
                if key in {"callback", "cb", "jsonp", "jsoncallback"} and value
            ),
            "",
        )
        if not callback_param and "javascript" not in content_type:
            continue
        match = jsonp_re.search(body[:300])
        if callback_param and match:
            findings.append(
                build_analyzer_result(
                    url,
                    response=response,
                    callback_parameter=callback_param,
                    detected_function=match.group(1),
                    content_type=response.get("content_type", ""),
                )
            )
    return findings


def frontend_config_exposure_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    patterns = [
        ("firebase_config", re.compile(r"firebase[a-z0-9_]*\s*[:=]\s*\{", re.IGNORECASE)),
        (
            "api_base_url",
            re.compile(r"(api[_-]?base|base[_-]?url)\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        ),
        (
            "sentry_dsn",
            re.compile(r"https://[a-z0-9]+@o\d+\.ingest\.sentry\.io/\d+", re.IGNORECASE),
        ),
        ("graphql_endpoint", re.compile(r"/graphql\b", re.IGNORECASE)),
    ]
    for response in responses:
        body = response.get("body_text") or ""
        content_type = str(response.get("content_type", "")).lower()
        if not any(token in content_type for token in ("javascript", "json", "html")):
            continue
        hits = [label for label, pattern in patterns if pattern.search(body[:6000])]
        if hits:
            findings.append(
                build_analyzer_result(
                    response.get("url", ""),
                    response=response,
                    content_type=response.get("content_type", ""),
                    indicators=hits,
                )
            )
    return findings


def directory_listing_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for response in responses:
        body = (response.get("body_text") or "")[:4000]
        lowered = body.lower()
        if "index of /" not in lowered:
            continue
        if "parent directory" not in lowered and "last modified" not in lowered:
            continue
        url = response.get("url", "")
        findings.append(
            build_analyzer_result(url, response=response, indicator="directory_listing_pattern")
        )
    return findings


def debug_artifact_checker(urls: set[str], responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    debug_tokens = ("/debug", "/actuator", "/trace", "/__debug__", "/.env", "/swagger", "/openapi")
    for url in sorted(urls):
        lowered = url.lower()
        if any(token in lowered for token in debug_tokens):
            findings.append(build_analyzer_result(url, indicator="debug_path_hint"))
    for response in responses:
        body = (response.get("body_text") or "")[:4000].lower()
        if any(
            token in body
            for token in ("swagger-ui", "openapi", "whitelabel error page", "actuator")
        ):
            url = response.get("url", "")
            findings.append(
                build_analyzer_result(url, response=response, indicator="debug_response_hint")
            )
    return findings[:120]


def technology_fingerprint(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for response in responses:
        combined = " ".join(
            [
                response.get("content_type", ""),
                json_headers(response.get("headers", {})),
                response.get("body_text", "")[:4000],
            ]
        )
        for label, pattern in TECH_SIGNATURES:
            if not pattern.search(combined):
                continue
            dedupe_signature = dedup_key(response.get("url", ""), label)
            if dedupe_signature in seen:
                continue
            seen.add(dedupe_signature)
            findings.append(
                {
                    "url": response.get("url", ""),
                    "technology": label,
                    "status_code": response.get("status_code"),
                }
            )
    findings.sort(key=lambda item: (item["technology"], item["url"]))
    return findings[:150]
