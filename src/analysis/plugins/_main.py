from typing import Any

from src.core.plugins import list_plugins, register_plugin

from .active import ACTIVE_PLUGIN_SPECS
from .base import _spec
from .behavior import BEHAVIOR_PLUGIN_SPECS
from .passive import PASSIVE_PLUGIN_SPECS

DETECTOR_SPEC = "detector_spec"

_SPECS_REGISTERED = False


def _register_specs() -> None:
    global _SPECS_REGISTERED
    if _SPECS_REGISTERED:
        return

    specs = (
        (
            _spec(
                "sensitive_data_scanner",
                "Sensitive Data Scanner",
                "Look for secrets and sensitive patterns in fetched response bodies.",
                "exposure",
            ),
            _spec(
                "header_checker",
                "Header Checker",
                "Flag missing HSTS, CSP, referrer, permissions, and related response headers.",
                "exposure",
            ),
            _spec(
                "cookie_security_checker",
                "Cookie Security",
                "Inspect Set-Cookie headers for missing Secure, HttpOnly, and SameSite protections.",
                "exposure",
            ),
            _spec(
                "cors_misconfig_checker",
                "Passive CORS Review",
                "Review observed CORS headers for wildcard credentials, null origin allowance, and missing Vary handling.",
                "exposure",
            ),
            _spec(
                "cache_control_checker",
                "Cache Control Review",
                "Flag auth and API responses that look cacheable when they should likely be private or no-store.",
                "exposure",
            ),
            _spec(
                "jsonp_endpoint_checker",
                "JSONP Detector",
                "Spot callback-style JSONP endpoints that can expose cross-origin data to script tags.",
                "redirect",
            ),
            _spec(
                "frontend_config_exposure_checker",
                "Frontend Config Review",
                "Scan frontend responses for exposed config objects, API base URLs, DSNs, and GraphQL hints.",
                "exposure",
            ),
            _spec(
                "directory_listing_checker",
                "Directory Listing",
                "Detect passive signs of exposed directory indexing in fetched responses.",
                "exposure",
            ),
            _spec(
                "debug_artifact_checker",
                "Debug Artifact Review",
                "Flag debug, actuator, swagger, env, and other diagnostic exposure hints from URLs and responses.",
                "exposure",
            ),
            _spec(
                "stored_xss_signal_detector",
                "Stored XSS Signals",
                "Look for dangerous markup inside comment, message, bio, description, and similar response fields.",
                "exposure",
            ),
            _spec(
                "token_leak_detector",
                "Token Leak Detector",
                "Hunt for token-like values and referer leakage across URLs and responses.",
                "session",
            ),
            _spec(
                "csrf_protection_checker",
                "CSRF Protection Checker",
                "Identify state-changing endpoints missing CSRF tokens, SameSite cookies, or anti-CSRF headers.",
                "session",
            ),
            _spec(
                "ssti_surface_detector",
                "SSTI Surface Detector",
                "Detect template engine fingerprints and parameters vulnerable to Server-Side Template Injection.",
                "session",
            ),
            _spec(
                "file_upload_surface_detector",
                "File Upload Surface Detector",
                "Identify endpoints that accept file uploads and may be vulnerable to unrestricted upload attacks.",
                "session",
            ),
            _spec(
                "vulnerable_component_detector",
                "Vulnerable Component Detector",
                "Detect exposed version strings, framework fingerprints, and known vulnerable component indicators.",
                "exposure",
            ),
            _spec(
                "business_logic_tampering_detector",
                "Business Logic Tampering Detector",
                "Detect endpoints with price, quantity, and discount parameters vulnerable to client-side manipulation.",
                "session",
            ),
            _spec(
                "rate_limit_bypass_detector",
                "Rate Limit Bypass Detector",
                "Test rate limiting enforcement and detect bypass via header manipulation (X-Forwarded-For, X-Real-IP).",
                "active",
            ),
            _spec(
                "jwt_security_analyzer",
                "JWT Security Analyzer",
                "Analyze JWT tokens for weak algorithms, missing claims, expiration issues, and algorithm confusion vulnerabilities.",
                "session",
            ),
            _spec(
                "http_smuggling_detector",
                "HTTP Smuggling Detector",
                "Test for HTTP request smuggling vulnerabilities via Transfer-Encoding/Content-Length header confusion.",
                "active",
            ),
            _spec(
                "ssrf_candidate_finder",
                "SSRF Candidate Finder",
                "Highlight URL and callback-style parameters that look SSRF-relevant.",
                "redirect",
            ),
            _spec(
                "application_ssrf_vector_detector",
                "Application SSRF Vector Detector",
                "Detect Grafana, Kibana, Jenkins, GitLab, and other apps with known SSRF-prone proxy endpoints.",
                "active",
            ),
            _spec(
                "proxy_ssrf_probe",
                "Proxy/Relay SSRF Probe",
                "Test URL preview, webhook, RSS, image proxy, and PDF generation endpoints for SSRF vulnerabilities.",
                "active",
            ),
            _spec(
                "ssrf_active_probe",
                "SSRF Active Probe",
                "Actively test URL parameters with internal and collaborator-style payloads.",
                "active",
            ),
            _spec(
                "open_redirect_active_probe",
                "Open Redirect Probe",
                "Test redirect and callback parameters with external URL payloads.",
                "active",
            ),
            _spec(
                "crlf_injection_probe",
                "CRLF Injection Probe",
                "Test parameters for response splitting and header injection via CRLF sequences.",
                "active",
            ),
            _spec(
                "host_header_injection_probe",
                "Host Header Probe",
                "Manipulate Host and X-Forwarded-Host headers to test for poisoning.",
                "active",
            ),
            _spec(
                "ssti_active_probe",
                "SSTI Active Probe",
                "Send template injection payloads to template-relevant parameters.",
                "active",
            ),
            _spec(
                "nosql_injection_probe",
                "NoSQL Injection Probe",
                "Test JSON body parameters with MongoDB-style operator payloads.",
                "active",
            ),
            _spec(
                "deserialization_probe",
                "Deserialization Probe",
                "Send crafted serialized objects to parameters that look like serialized data.",
                "active",
            ),
            _spec(
                "dns_record_analyzer",
                "DNS Record Analyzer",
                "Check for DNS misconfiguration signals, dangling CNAMEs, third-party domain exposure, and CDN/WAF provider detection.",
                "exposure",
            ),
            _spec(
                "clickjacking_test",
                "Clickjacking Active Test",
                "Actively test endpoints for clickjacking vulnerabilities by checking missing framing protections and testing actual framing behavior.",
                "active",
            ),
            _spec(
                "ssrf_oob_validator",
                "SSRF Out-of-Band Validator",
                "Actively test URL parameters with internal and collaborator-style payloads for SSRF vulnerabilities.",
                "active",
            ),
            _spec(
                "ldap_injection_surface_analyzer",
                "LDAP Injection Surface Analyzer",
                "Detect LDAP injection surface indicators in URLs and response bodies, including LDAP parameters, error messages, and authentication endpoints.",
                "passive",
            ),
            _spec(
                "mass_assignment_detector",
                "Mass Assignment Detector",
                "Actively test POST/PUT endpoints for mass assignment vulnerabilities by injecting sensitive fields into JSON request bodies and comparing responses.",
                "active",
            ),
            _spec(
                "cache_deception_probe",
                "Cache Deception Probe",
                "Actively test for web cache deception by requesting sensitive endpoints with static file extensions and path normalization tricks, checking for cacheable responses containing user-specific data.",
                "active",
            ),
            _spec(
                "email_header_injection_probe",
                "Email Header Injection Probe",
                "Test email-related parameters for CRLF injection vulnerabilities that could allow header injection into outbound emails.",
                "active",
            ),
            _spec(
                "xml_bomb_detector",
                "XML Bomb Detector",
                "Detect XML entity expansion (Billion Laughs, Quadratic Blowup) and XXE vulnerabilities in XML-processing endpoints.",
                "active",
            ),
            _spec(
                "token_lifetime_analyzer",
                "Token Lifetime Analyzer",
                "Analyze authentication tokens for lifetime, rotation, algorithm, and exposure issues across responses.",
                "passive",
            ),
            _spec(
                "deserialization_language_probe",
                "Deserialization Language Probe",
                "Detect language-specific deserialization formats and test for insecure deserialization across multiple serialization libraries.",
                "active",
            ),
            _spec(
                "oauth_misconfiguration_detector",
                "OAuth Misconfiguration Detector",
                "Passively analyze OAuth/SAML endpoints for implicit flow, missing PKCE, token exposure, missing state, open redirect, scope over-permissioning, and client ID exposure.",
                "passive",
            ),
            _spec(
                "xxe_surface_detector",
                "XXE Surface Detector",
                "Detect XML processing endpoints, SOAP/XML-RPC services, SAML endpoints, RSS/Atom feeds, and XXE error patterns in responses.",
                "passive",
            ),
            _spec(
                "open_redirect_detector",
                "Open Redirect Detector",
                "Identify redirect parameters, meta refresh tags, JavaScript redirects, and Location header issues that may enable open redirect attacks.",
                "passive",
            ),
            _spec(
                "clickjacking_detector",
                "Clickjacking Detector",
                "Detect missing or weak X-Frame-Options, missing CSP frame-ancestors, absent frame-busting JavaScript, and iframe-susceptible endpoints.",
                "passive",
            ),
            _spec(
                "logging_failure_detector",
                "Logging Security Detector",
                "Find log file exposure, logging endpoints, sensitive data in URLs, verbose logging headers, and debug logging indicators in responses.",
                "passive",
            ),
            _spec(
                "csrf_active_probe",
                "CSRF Active Probe",
                "Test state-changing endpoints for missing CSRF protections via token omission, invalid tokens, and Origin/Referer bypass attempts.",
                "active",
            ),
            _spec(
                "xpath_injection_probe",
                "XPath Injection Probe",
                "Send XPath injection payloads to XML-backed endpoint parameters and detect error patterns, auth bypass, and response divergence.",
                "active",
            ),
            _spec(
                "hpp_active_probe",
                "HTTP Parameter Pollution Probe",
                "Test endpoints with duplicate parameters, encoded variants, and array-style formatting to detect parameter parsing inconsistencies.",
                "active",
            ),
            _spec(
                "jwt_manipulation_probe",
                "JWT Manipulation Probe",
                "Test algorithm confusion, none algorithm attack, claim modification, kid path traversal, jku injection, and expired token acceptance.",
                "active",
            ),
            _spec(
                "websocket_hijacking_probe",
                "WebSocket Hijacking Probe",
                "Test WebSocket endpoints for cross-origin acceptance, missing origin validation, and authentication bypass.",
                "active",
            ),
            _spec(
                "idor_active_probe",
                "IDOR Active Probe",
                "Test numeric IDs, UUIDs, and object reference parameters for insecure direct object reference vulnerabilities via ID manipulation.",
                "active",
            ),
            _spec(
                "file_upload_active_probe",
                "File Upload Active Probe",
                "Test upload endpoints with dangerous extensions, double extensions, null bytes, MIME manipulation, magic bytes, and polyglot files.",
                "active",
            ),
            _spec(
                "cookie_manipulation_probe",
                "Cookie Manipulation Probe",
                "Test cookie tampering, flag removal, base64/JSON decoding, session fixation, overflow, and injection of privileged cookie names.",
                "active",
            ),
            _spec(
                "auth_bypass_check",
                "Auth Bypass Active Check",
                "Actively test endpoints for authentication bypass via JWT stripping, cookie manipulation, and parameter injection.",
                "active",
            ),
            _spec(
                "tenant_isolation_check",
                "Tenant Isolation Check",
                "Detect multi-tenant applications and test tenant isolation for horizontal and vertical privilege escalation vulnerabilities.",
                "active",
            ),
        )
        + ACTIVE_PLUGIN_SPECS
        + PASSIVE_PLUGIN_SPECS
        + BEHAVIOR_PLUGIN_SPECS
    )

    for s in specs:
        register_plugin(DETECTOR_SPEC, s.key)(s)

    _SPECS_REGISTERED = True


def _get_specs() -> tuple[Any, ...]:
    _register_specs()
    return tuple(reg.provider for reg in list_plugins(DETECTOR_SPEC))


# We use a helper to ensure registration happens before access
# but for backward compatibility we keep the module-level names.

_SPECS_CACHE: tuple[Any, ...] | None = None


def get_analysis_plugin_specs() -> tuple[Any, ...]:
    global _SPECS_CACHE
    if _SPECS_CACHE is None:
        _SPECS_CACHE = _get_specs()
    return _SPECS_CACHE


# Re-export for backward compatibility
ANALYSIS_PLUGIN_SPECS = get_analysis_plugin_specs()
PASSIVE_CHECK_NAMES = tuple(spec.key for spec in ANALYSIS_PLUGIN_SPECS)
ANALYSIS_PLUGIN_SPECS_BY_KEY = {spec.key: spec for spec in ANALYSIS_PLUGIN_SPECS}


def analysis_check_options() -> list[dict[str, object]]:
    return [
        {
            "name": spec.key,
            "label": spec.label,
            "description": spec.description,
            "group": spec.group,
            "slug": spec.slug,
        }
        for spec in ANALYSIS_PLUGIN_SPECS
    ]
