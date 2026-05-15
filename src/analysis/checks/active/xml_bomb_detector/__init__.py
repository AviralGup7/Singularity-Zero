"""XML Bomb / Entity Expansion Detector (Active).

Detects XML entity expansion vulnerabilities including Billion Laughs attacks,
Quadratic Blowup attacks, and XML External Entity (XXE) injection. These
vulnerabilities can lead to denial-of-service, file disclosure, or server-side
request forgery through malicious XML payloads.

The check identifies XML-processing endpoints by examining URL extensions,
content types, response bodies, and path patterns. It then sends crafted XML
bomb payloads and measures responses for timeout indicators, error messages
revealing parser details, and file content leakage.

This package modularizes the XML bomb detector into separate files
for better maintainability and AI-agent editability.
"""

from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.analysis.helpers import classify_endpoint, endpoint_signature

from ._constants import (
    BASE64_PHP_RE,
    BOOT_INI_RE,
    ETC_PASSWD_RE,
    FILE_CONTENT_LEAK_RE,
    TIMEOUT_THRESHOLD_SECONDS,
    WIN_INI_RE,
    XML_BOMB_DETECTOR_SPEC,
    XML_ERROR_PATTERNS,
    XML_PARSER_DISCLOSURE_PATTERNS,
    XXE_SUCCESS_PATTERNS,
)
from ._helpers import (
    build_finding,
    compute_confidence,
    determine_severity,
    get_xml_bomb_payloads,
    is_xml_endpoint,
    normalize_headers,
    safe_request,
    severity_score,
)

__all__ = ["xml_bomb_detector", "XML_BOMB_DETECTOR_SPEC", "compute_confidence", "severity_score"]


def xml_bomb_detector(
    priority_urls: list[dict[str, Any]],
    response_cache: Any | None = None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Detect XML entity expansion and XXE vulnerabilities."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        if classify_endpoint(url) == "STATIC":
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        baseline_resp = None
        baseline_content_type = ""
        baseline_body = ""
        if response_cache is not None:
            try:
                baseline_resp = response_cache.request(
                    url,
                    headers={"Cache-Control": "no-cache", "Accept": "application/xml"},
                )
            except Exception:
                baseline_resp = None
        if baseline_resp is None:
            baseline_resp = safe_request(url, headers={"Accept": "application/xml"})

        baseline_body = str(baseline_resp.get("body") or baseline_resp.get("body_text") or "")[
            :5000
        ]
        baseline_headers = normalize_headers(baseline_resp.get("headers"))
        baseline_content_type = baseline_headers.get("content-type", "")

        is_xml = is_xml_endpoint(url, baseline_body, baseline_content_type)

        query_pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
        xml_query_params = [
            (i, k, v)
            for i, (k, v) in enumerate(query_pairs)
            if any(
                token in k.lower()
                for token in (
                    "xml",
                    "data",
                    "payload",
                    "body",
                    "request",
                    "input",
                    "soap",
                    "envelope",
                )
            )
        ]
        has_xml_params = len(xml_query_params) > 0

        if not is_xml and not has_xml_params:
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        payloads = get_xml_bomb_payloads()

        for payload_name, payload_body in payloads:
            if len(url_probes) >= 4:
                break

            request_body = payload_body.encode("utf-8")
            probe_resp = None
            if response_cache is not None:
                try:
                    probe_resp = response_cache.request(
                        url,
                        method="POST",
                        headers={
                            "Cache-Control": "no-cache",
                            "Content-Type": "application/xml",
                            "X-XML-Bomb-Probe": payload_name,
                        },
                        body=request_body,
                    )
                except Exception:
                    probe_resp = None
            if probe_resp is None:
                probe_resp = safe_request(
                    url,
                    method="POST",
                    headers={
                        "Cache-Control": "no-cache",
                        "Content-Type": "application/xml",
                        "X-XML-Bomb-Probe": payload_name,
                    },
                    body=request_body,
                    timeout=12,
                )

            body = str(probe_resp.get("body") or probe_resp.get("body_text") or "")[:5000]
            status = int(probe_resp.get("status") or probe_resp.get("status_code") or 0)
            elapsed = float(probe_resp.get("elapsed") or 0)
            normalize_headers(probe_resp.get("headers"))

            issues_for_hit: list[str] = []

            if payload_name in ("xxe_file_read", "xxe_netdoc"):
                if ETC_PASSWD_RE.search(body):
                    issues_for_hit.append("xxe_file_read_confirmed")
                elif FILE_CONTENT_LEAK_RE.search(body):
                    issues_for_hit.append("xxe_file_read_confirmed")

            if payload_name == "xxe_windows":
                if WIN_INI_RE.search(body) or BOOT_INI_RE.search(body):
                    issues_for_hit.append("xxe_windows_file_read")

            if payload_name == "xxe_php_filter":
                if BASE64_PHP_RE.search(body):
                    issues_for_hit.append("xxe_php_filter_read")

            if payload_name == "billion_laughs":
                if elapsed > TIMEOUT_THRESHOLD_SECONDS:
                    issues_for_hit.append("xml_bomb_timeout")
                elif status == 500 and any(p.search(body) for p in XML_ERROR_PATTERNS):
                    issues_for_hit.append("xml_bomb_error")

            if payload_name == "quadratic_blowup":
                if status == 200 and len(body) > 100:
                    issues_for_hit.append("quadratic_blowup_accepted")
                elif status == 500 and any(p.search(body) for p in XML_ERROR_PATTERNS):
                    issues_for_hit.append("xml_bomb_error")

            if payload_name in ("xxe_external_dtd", "xxe_parameter_entity"):
                if any(p.search(body) for p in XML_ERROR_PATTERNS):
                    issues_for_hit.append("xxe_external_dtd_fetch")

            if payload_name == "xxe_expect":
                if any(p.search(body) for p in XXE_SUCCESS_PATTERNS):
                    issues_for_hit.append("xxe_file_read_confirmed")
                elif any(p.search(body) for p in XML_ERROR_PATTERNS):
                    issues_for_hit.append("xxe_error_parser_detail")

            # Check for XML parser disclosure in error messages
            if status >= 400:
                for pattern in XML_PARSER_DISCLOSURE_PATTERNS:
                    if pattern.search(body):
                        issues_for_hit.append("xml_parser_disclosure")
                        break

            if issues_for_hit:
                url_issues.extend(issues_for_hit)
                url_probes.append(
                    {
                        "payload_type": payload_name,
                        "status_code": status,
                        "elapsed": elapsed,
                        "issues": issues_for_hit,
                    }
                )

        if url_probes:
            severity = determine_severity(url_issues)
            title = f"XML bomb/XXE vulnerability detected: {url}"
            explanation = (
                f"Endpoint '{url}' shows indicators of XML entity expansion or XXE "
                f"vulnerability. Detected issues: {', '.join(url_issues[:8])}. "
                f"This endpoint processes XML payloads and may be vulnerable to "
                f"Billion Laughs, Quadratic Blowup, or XXE attacks."
            )

            finding = build_finding(
                url=url,
                severity=severity,
                title=title,
                category="xml_bomb_xxe",
                signals=url_issues[:12],
                evidence={
                    "probes": url_probes,
                    "baseline_content_type": baseline_content_type,
                    "is_xml_endpoint": is_xml,
                    "has_xml_params": has_xml_params,
                },
                explanation=explanation,
                status_code=status,
            )
            findings.append(finding)

    findings.sort(
        key=lambda item: (-item.get("confidence", 0), -item.get("score", 0), item.get("url", ""))
    )
    return findings[:limit]
