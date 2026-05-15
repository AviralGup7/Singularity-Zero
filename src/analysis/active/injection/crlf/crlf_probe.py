"""Main CRLF injection probe orchestrator."""

import uuid
from typing import Any
from urllib.parse import parse_qsl, quote, urlparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache

from .._confidence import probe_confidence, probe_severity
from ._crlf_constants import CRLF_PROBE_PAYLOADS
from ._heuristic import _heuristic_check
from ._path_variants import generate_path_variants
from ._url_variants import generate_crlf_variants
from ._user_agents import _rotate_user_agent
from ._validator import _check_crlf_vulnerability
from ._waf_detector import _detect_waf


def crlf_injection_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test parameters and paths with CRLF sequences for header injection.

    Features:
    - WAF detection before scanning (Feature 1)
    - Heuristic pre-scan to skip futile targets (Feature 4)
    - Path injection when no query params exist (Feature 2)
    - POST body injection detection (Feature 3)
    - Complex CRLF-to-XSS payloads (Feature 5)
    - User-Agent rotation on every request (Feature 6)

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of CRLF injection findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    crlf_param_names = {
        "redirect",
        "url",
        "next",
        "callback",
        "return",
        "dest",
        "target",
        "uri",
        "path",
        "page",
        "forward",
        "go",
        "out",
        "ref",
        "referer",
        "continue",
        "goto",
        "back",
        "redir",
        "location",
        "destination",
        "returnto",
        "return_url",
        "action",
        "dest_url",
        "redirect_url",
        "redirect_uri",
        "returnurl",
        "redirecturl",
        "next_url",
        "nexturl",
    }

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "")).strip()
        if not url:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

        if query_pairs:
            heuristic_token = uuid.uuid4().hex[:8]
            precheck = _heuristic_check(url, response_cache, heuristic_token)
            if precheck:
                if precheck["waf_detected"]:
                    waf_name = precheck["waf_detected"]
                    findings.append(
                        {
                            "url": url,
                            "endpoint_key": endpoint_key,
                            "endpoint_base_key": endpoint_base_key(url),
                            "endpoint_type": classify_endpoint(url),
                            "issues": [f"waf_detected_{waf_name.lower().replace(' ', '_')}"],
                            "probes": [
                                {
                                    "parameter": "__WAF__",
                                    "payload": "heuristic_probe",
                                    "crlf_sequence": "%0d%0a",
                                    "variant": "waf_detection",
                                    "method": {"type": "waf_detection", "waf_name": waf_name},
                                    "status_code": 0,
                                    "issues": [f"waf_{waf_name.lower().replace(' ', '_')}"],
                                }
                            ],
                            "probe_token": heuristic_token,
                            "variant_matrix_size": 0,
                            "confidence": 30,
                            "severity": "info",
                        }
                    )
                    if precheck["blocked"]:
                        continue

        probe_token = uuid.uuid4().hex[:12]

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []
        total_variants_tested = 0

        post_endpoint = url_entry.get("method", "").upper() == "POST"

        if query_pairs:
            crlf_params = [
                (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in crlf_param_names
            ]
            if not crlf_params:
                crlf_params = []

            for idx, param_name, _param_value in crlf_params:
                if len(url_probes) >= 3:
                    break

                variants = generate_crlf_variants(url, idx, param_name, probe_token)
                if not variants:
                    continue
                total_variants_tested += len(variants)

                confirmed_types: set[str] = set()

                for variant in variants:
                    if len(url_probes) >= 10:
                        break

                    test_url = variant["url"]
                    variant_name = variant["variant_name"]
                    expected_header = variant["expected_header"]
                    expected_value = variant["expected_value"]

                    payload_name = (
                        variant_name.split(":")[0] if ":" in variant_name else variant_name
                    )

                    if payload_name in confirmed_types:
                        continue

                    ua = _rotate_user_agent()
                    response = response_cache.request(
                        test_url,
                        headers={
                            "User-Agent": ua,
                            "Cache-Control": "no-cache",
                            "X-CRLF-Probe": probe_token,
                        },
                    )
                    if not response:
                        continue

                    body = str(response.get("body_text", "") or "")[:16000]
                    status = int(response.get("status_code") or 0)
                    headers = {
                        str(key).lower(): str(value)
                        for key, value in (response.get("headers") or {}).items()
                    }

                    waf = _detect_waf(status, headers, body)
                    if waf:
                        if "waf_detected" not in [
                            i for p in url_probes for i in p.get("issues", [])
                        ]:
                            url_probes.append(
                                {
                                    "parameter": param_name,
                                    "payload": "waf_fingerprint",
                                    "crlf_sequence": "",
                                    "variant": f"waf_{waf.lower().replace(' ', '_')}",
                                    "method": {"type": "waf_detection", "waf_name": waf},
                                    "status_code": status,
                                    "issues": [f"waf_{waf.lower().replace(' ', '_')}"],
                                }
                            )

                    is_set_cookie = payload_name in ("set_cookie",)
                    is_response_split = payload_name in (
                        "response_split",
                        "status_code_inject",
                        "xss_via_split",
                        "content_length_zero",
                        "full_response_split",
                        "x_xss_protection_zero",
                        "split_with_xss_redirect",
                        "split_set_cookie_xss",
                        "cache_poisoning_xss",
                        "split_meta_redirect",
                        "split_img_onerror",
                        "split_svg_xss",
                        "split_jsonp_hijack",
                        "double_split_xss",
                        "split_html_inject",
                    )

                    issues_for_hit = _check_crlf_vulnerability(
                        headers=headers,
                        body=body,
                        expected_header=expected_header,
                        expected_value=expected_value,
                        token=probe_token,
                        is_set_cookie=is_set_cookie,
                        is_response_split=is_response_split,
                    )

                    if issues_for_hit:
                        url_issues.extend(issues_for_hit)
                        confirmed_types.add(payload_name)
                        url_probes.append(
                            {
                                "parameter": param_name,
                                "payload": variant["payload"],
                                "crlf_sequence": variant["crlf_seq"],
                                "variant": variant_name,
                                "method": {
                                    "type": "session_cookie"
                                    if is_set_cookie
                                    else "response_split"
                                    if is_response_split
                                    else "header_injection",
                                    "expected_header": expected_header,
                                    "expected_value": expected_value,
                                },
                                "status_code": status,
                                "issues": issues_for_hit,
                            }
                        )
                        break

        if not query_pairs or not url_probes:
            path_variants = generate_path_variants(url, probe_token)
            if path_variants:
                total_variants_tested += min(len(path_variants), 50)
                confirmed_types = set()

                for variant in path_variants[:50]:
                    if len(url_probes) >= 10:
                        break

                    test_url = variant["url"]
                    variant_name = variant["variant_name"]
                    expected_header = variant["expected_header"]
                    expected_value = variant["expected_value"]

                    payload_name = (
                        variant_name.split(":")[1] if ":" in variant_name else variant_name
                    )

                    if payload_name in confirmed_types:
                        continue

                    ua = _rotate_user_agent()
                    response = response_cache.request(
                        test_url,
                        headers={
                            "User-Agent": ua,
                            "Cache-Control": "no-cache",
                            "X-CRLF-Probe": probe_token,
                        },
                    )
                    if not response:
                        continue

                    body = str(response.get("body_text", "") or "")[:16000]
                    status = int(response.get("status_code") or 0)
                    headers = {
                        str(key).lower(): str(value)
                        for key, value in (response.get("headers") or {}).items()
                    }

                    is_response_split = payload_name in (
                        "response_split",
                        "status_code_inject",
                        "xss_via_split",
                        "content_length_zero",
                        "full_response_split",
                        "x_xss_protection_zero",
                        "split_with_xss_redirect",
                        "split_set_cookie_xss",
                        "cache_poisoning_xss",
                        "split_meta_redirect",
                        "split_img_onerror",
                        "split_svg_xss",
                        "split_jsonp_hijack",
                        "double_split_xss",
                        "split_html_inject",
                    )

                    issues_for_hit = _check_crlf_vulnerability(
                        headers=headers,
                        body=body,
                        expected_header=expected_header,
                        expected_value=expected_value,
                        token=probe_token,
                        is_set_cookie=False,
                        is_response_split=is_response_split,
                    )

                    if issues_for_hit:
                        url_issues.extend(issues_for_hit)
                        confirmed_types.add(payload_name)
                        url_probes.append(
                            {
                                "parameter": "__PATH__",
                                "payload": variant["payload"],
                                "crlf_sequence": variant["crlf_seq"],
                                "variant": variant_name,
                                "method": {
                                    "type": "path_injection",
                                    "expected_header": expected_header,
                                    "expected_value": expected_value,
                                },
                                "status_code": status,
                                "issues": issues_for_hit,
                            }
                        )
                        break

        if post_endpoint:
            post_payload = _build_payload("%0d%0a", CRLF_PROBE_PAYLOADS[0]["template"], probe_token)
            ua = _rotate_user_agent()
            response = response_cache.request(
                url,
                method="POST",
                headers={
                    "User-Agent": ua,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cache-Control": "no-cache",
                    "X-CRLF-Probe": probe_token,
                },
                body=f"data={quote(post_payload, safe='')}",
            )
            if response:
                body = str(response.get("body_text", "") or "")[:16000]
                status = int(response.get("status_code") or 0)
                headers = {
                    str(key).lower(): str(value)
                    for key, value in (response.get("headers") or {}).items()
                }

                issues_for_hit = _check_crlf_vulnerability(
                    headers=headers,
                    body=body,
                    expected_header="x-crlf-test",
                    expected_value=f"detected-{probe_token}",
                    token=probe_token,
                    is_set_cookie=False,
                    is_response_split=False,
                )

                if issues_for_hit:
                    url_issues.extend(issues_for_hit)
                    url_probes.append(
                        {
                            "parameter": "__POST_BODY__",
                            "payload": post_payload,
                            "crlf_sequence": "%0d%0a",
                            "variant": "post_body:basic",
                            "method": {
                                "type": "post_body_injection",
                                "expected_header": "x-crlf-test",
                                "expected_value": f"detected-{probe_token}",
                            },
                            "status_code": status,
                            "issues": issues_for_hit,
                        }
                    )

        if url_probes:
            unique_issues = list(dict.fromkeys(url_issues))
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": unique_issues,
                    "probes": url_probes,
                    "probe_token": probe_token,
                    "variant_matrix_size": total_variants_tested,
                    "confidence": probe_confidence(unique_issues),
                    "severity": probe_severity(unique_issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]


def _build_payload(crlf_seq: str, payload_template: str, token: str) -> str:
    """Build a concrete CRLF payload from template, escape sequence, and token."""
    space = "%20"
    return payload_template.format(crlf=crlf_seq, space=space, token=token)
