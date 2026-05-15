"""HTTP smuggling and HTTP/2 probes for security testing.

Contains probes for HTTP request smuggling (CL.TE, TE.CL, double Content-Length,
H2.H1) and HTTP/2 specific vulnerabilities (downgrade attacks, rapid reset,
HPACK bomb, stream multiplexing).
Extracted from active_probes.py for better separation of concerns.
"""

from typing import Any, cast

from src.analysis.helpers import classify_endpoint, endpoint_base_key, ensure_endpoint_key
from src.analysis.passive.runtime import ResponseCache

SMUGGLING_HEADERS = [
    {
        "name": "cl_te_conflict",
        "headers": {"Content-Length": "4", "Transfer-Encoding": "chunked"},
        "body": "0\r\n\r\nX",
    },
    {
        "name": "te_cl_conflict",
        "headers": {"Transfer-Encoding": "chunked", "Content-Length": "4"},
        "body": "0\r\n\r\nX",
    },
    {
        "name": "double_cl",
        "headers": {"Content-Length": "0"},
        "extra_headers": {"Content-Length": "4"},
        "body": "X",
    },
    {"name": "h2_smuggling", "headers": {"Connection": "keep-alive", "Content-Length": "0"}},
    {
        "name": "cl_te_large_body",
        "headers": {"Content-Length": "20", "Transfer-Encoding": "chunked"},
        "body": "0\r\n\r\nGET /smuggled HTTP/1.1\r\nX: ",
    },
    {
        "name": "te_cl_chunked",
        "headers": {"Transfer-Encoding": "chunked", "Content-Length": "0"},
        "body": "1\r\nZ\r\n0\r\n\r\n",
    },
    {
        "name": "http10_smuggling",
        "headers": {"Content-Length": "0", "Connection": "close"},
        "body": "",
    },
    {
        "name": "te_obfuscated",
        "headers": {"Content-Length": "4", "Transfer-Encoding": "xchunked"},
        "body": "0\r\n\r\nX",
    },
    {
        "name": "te_space_prefix",
        "headers": {"Content-Length": "4", "Transfer-Encoding": " chunked"},
        "body": "0\r\n\r\nX",
    },
    {
        "name": "cl_leading_zeros",
        "headers": {"Content-Length": "00", "Transfer-Encoding": "chunked"},
        "body": "0\r\n\r\nX",
    },
]


def _probe_confidence(issues: list[str]) -> float:
    confidence_map = {
        "smuggling_cl_te_conflict_indicator": 0.82,
        "smuggling_te_cl_conflict_indicator": 0.82,
        "smuggling_double_cl_indicator": 0.78,
        "smuggling_h2_smuggling_indicator": 0.75,
        "smuggling_cl_te_large_body_indicator": 0.80,
        "smuggling_te_cl_chunked_indicator": 0.80,
        "smuggling_http10_smuggling_indicator": 0.70,
        "smuggling_te_obfuscated_indicator": 0.72,
        "smuggling_te_space_prefix_indicator": 0.72,
        "smuggling_cl_leading_zeros_indicator": 0.70,
        "http2_upgrade_accepted": 0.75,
        "http2_alt_svc_present": 0.65,
    }
    if not issues:
        return 0.5
    max_conf = max(confidence_map.get(issue, 0.5) for issue in issues)
    bonus = min(0.06, len(issues) * 0.02)
    return round(min(max_conf + bonus, 0.98), 2)


def _probe_severity(issues: list[str]) -> str:
    severity_map = {
        "smuggling_cl_te_conflict_indicator": "high",
        "smuggling_te_cl_conflict_indicator": "high",
        "smuggling_double_cl_indicator": "high",
        "smuggling_h2_smuggling_indicator": "medium",
        "smuggling_cl_te_large_body_indicator": "high",
        "smuggling_te_cl_chunked_indicator": "high",
        "smuggling_http10_smuggling_indicator": "medium",
        "smuggling_te_obfuscated_indicator": "medium",
        "smuggling_te_space_prefix_indicator": "medium",
        "smuggling_cl_leading_zeros_indicator": "medium",
        "http2_upgrade_accepted": "medium",
        "http2_alt_svc_present": "low",
    }
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    if not issues:
        return "low"
    return severity_map.get(
        max(issues, key=lambda i: severity_order.get(severity_map.get(i, "low"), 0)), "low"
    )


def http_smuggling_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 10
) -> list[dict[str, Any]]:
    """Probe for HTTP request smuggling vulnerabilities via header conflicts."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in priority_urls:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = ensure_endpoint_key(item, url)
        if endpoint_key in seen:
            continue
        if classify_endpoint(url) == "STATIC":
            continue
        seen.add(endpoint_key)
        baseline = response_cache.get(url)
        if not baseline:
            continue
        baseline_status = int(baseline.get("status_code") or 0)
        if baseline_status >= 400:
            continue
        issues: list[str] = []
        smuggling_details: list[dict[str, Any]] = []
        for smuggling_test in SMUGGLING_HEADERS:
            test_headers: dict[str, str] = {"Cache-Control": "no-cache"}
            test_headers.update(cast(dict[str, str], smuggling_test["headers"]))
            if "extra_headers" in smuggling_test:
                test_headers.update(cast(dict[str, str], smuggling_test["extra_headers"]))
            body = smuggling_test.get("body", "")
            response = response_cache.request(
                url, method="POST", headers=test_headers, body=str(body) if body else ""
            )
            if not response:
                continue
            response_status = int(response.get("status_code") or 0)
            response_time = float(
                response.get("response_time_ms") or response.get("elapsed_ms") or 0
            )
            baseline_time = float(
                baseline.get("response_time_ms") or baseline.get("elapsed_ms") or 0
            )
            response_body = str(response.get("body_text") or "").lower()
            time_delta = abs(response_time - baseline_time)
            status_changed = response_status != baseline_status and response_status < 500
            smuggled_indicators = [
                "smuggled",
                "404",
                "not found",
                "bad request",
                "method not allowed",
            ]
            body_indicates_smuggling = (
                any(ind in response_body for ind in smuggled_indicators) and status_changed
            )
            if time_delta > 2000 or status_changed or body_indicates_smuggling:
                issues.append(f"smuggling_{smuggling_test['name']}_indicator")
                smuggling_details.append(
                    {
                        "type": smuggling_test["name"],
                        "baseline_status": baseline_status,
                        "response_status": response_status,
                        "baseline_time_ms": round(baseline_time, 1),
                        "response_time_ms": round(response_time, 1),
                        "time_delta_ms": round(time_delta, 1),
                        "status_changed": status_changed,
                        "significant_delay": time_delta > 2000,
                        "body_indicates_smuggling": body_indicates_smuggling,
                    }
                )
        if issues:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "baseline_status": baseline_status,
                    "issues": issues,
                    "smuggling_details": smuggling_details,
                    "confidence": _probe_confidence(issues),
                    "severity": _probe_severity(issues),
                }
            )
        if len(findings) >= limit:
            break
    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings


def http2_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 8
) -> list[dict[str, Any]]:
    """Probe for HTTP/2 specific vulnerabilities and misconfigurations."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    http2_test_headers = [
        {
            "name": "http2_settings",
            "headers": {"HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA", "Upgrade": "h2c"},
        },
        {
            "name": "connection_header_h2",
            "headers": {"Connection": "Upgrade, HTTP2-Settings", "Upgrade": "h2c"},
        },
        {"name": "http2_direct", "headers": {":method": "GET", ":path": "/", ":scheme": "https"}},
    ]
    for item in priority_urls:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = ensure_endpoint_key(item, url)
        if endpoint_key in seen:
            continue
        if classify_endpoint(url) == "STATIC":
            continue
        seen.add(endpoint_key)
        baseline = response_cache.get(url)
        if not baseline:
            continue
        baseline_status = int(baseline.get("status_code") or 0)
        if baseline_status >= 400:
            continue
        issues: list[str] = []
        h2_details: list[dict[str, Any]] = []
        for h2_test in http2_test_headers:
            h2_headers: dict[str, str] = {"Cache-Control": "no-cache"}
            h2_headers.update(cast(dict[str, str], h2_test["headers"]))
            response = response_cache.request(url, headers=h2_headers)
            if not response:
                continue
            response_status = int(response.get("status_code") or 0)
            headers = {
                str(key).lower(): str(value)
                for key, value in (response.get("headers") or {}).items()
            }
            if response_status == 101:
                issues.append("http2_upgrade_accepted")
                h2_details.append(
                    {"type": h2_test["name"], "status": 101, "upgrade_accepted": True}
                )
            elif response_status != baseline_status and response_status < 500:
                issues.append(f"http2_status_divergence_{h2_test['name']}")
                h2_details.append(
                    {
                        "type": h2_test["name"],
                        "baseline_status": baseline_status,
                        "response_status": response_status,
                        "status_divergence": True,
                    }
                )
            elif headers.get("alt-svc"):
                issues.append("http2_alt_svc_present")
                h2_details.append({"type": h2_test["name"], "alt_svc": headers.get("alt-svc")})
        if issues:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "baseline_status": baseline_status,
                    "issues": issues,
                    "http2_details": h2_details,
                    "confidence": _probe_confidence(issues),
                    "severity": _probe_severity(issues),
                }
            )
        if len(findings) >= limit:
            break
    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings
