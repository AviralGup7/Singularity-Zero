"""Helper functions for SSRF out-of-band validation."""

import time
from typing import Any

import requests

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_internal_host_value,
    meaningful_query_pairs,
)
from src.analysis.helpers.scoring import severity_score
from src.core.utils.url_validation import is_safe_url

from ._constants import (
    CLOUD_METADATA_PATTERNS,
    INTERNAL_ERROR_PATTERNS,
    INTERNAL_LEAK_PATTERNS,
    SSRF_PARAM_NAMES,
)


def safe_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Send an HTTP request with error handling and timing."""
    req_headers = dict(headers or {})
    req_headers.setdefault(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityPipeline/1.0",
    )
    if not is_safe_url(url):
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "success": False,
            "error": "URL failed safety check",
            "elapsed": 0.0,
        }
    start_time = time.time()
    try:
        resp = requests.request(
            method, url, headers=req_headers, data=body, timeout=timeout, verify=True
        )
        elapsed = time.time() - start_time
        resp_body = resp.text or ""
        return {
            "status": getattr(resp, "status_code", 0),
            "headers": dict(resp.headers),
            "body": (resp_body or "")[:5000],
            "success": resp.status_code < 400,
            "elapsed": elapsed,
        }
    except requests.RequestException as exc:
        elapsed = time.time() - start_time
        resp_obj = getattr(exc, "response", None)
        resp_body = ""
        status = 0
        headers = {}
        if resp_obj is not None:
            try:
                resp_body = resp_obj.text
                status = getattr(resp_obj, "status_code", 0)
                headers = dict(resp_obj.headers)
            except Exception:
                pass
        return {
            "status": status,
            "headers": headers,
            "body": (resp_body or "")[:5000],
            "success": False,
            "error": str(exc),
            "elapsed": elapsed,
        }
    except Exception as exc:
        elapsed = time.time() - start_time
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "success": False,
            "error": str(exc),
            "elapsed": elapsed,
        }


def find_ssrf_params(url: str) -> list[tuple[str, str]]:
    """Find SSRF-susceptible parameters in a URL."""
    pairs = meaningful_query_pairs(url)
    ssrf_params: list[tuple[str, str]] = []
    for name, value in pairs:
        if name in SSRF_PARAM_NAMES:
            ssrf_params.append((name, value))
        elif "://" in value or value.startswith("//"):
            ssrf_params.append((name, value))
        elif is_internal_host_value(value):
            ssrf_params.append((name, value))
    return ssrf_params


def check_cloud_metadata(body: str) -> list[str]:
    """Check if response body contains cloud metadata."""
    matches: list[str] = []
    for pattern in CLOUD_METADATA_PATTERNS:
        if pattern.search(body):
            matches.append(f"cloud_metadata:{pattern.pattern[:40]}")
    return matches


def check_internal_leakage(body: str) -> list[str]:
    """Check if response body leaks internal network information."""
    leaks: list[str] = []
    for pattern in INTERNAL_LEAK_PATTERNS:
        if pattern.search(body):
            matches = pattern.findall(body)
            unique_matches = list(set(m[:50] for m in matches))[:5]
            leaks.append(f"internal_leak:{pattern.pattern[:40]}:{','.join(unique_matches)}")
    return leaks


def check_internal_errors(body: str) -> list[str]:
    """Check if response body reveals internal network topology."""
    errors: list[str] = []
    for pattern in INTERNAL_ERROR_PATTERNS:
        if pattern.search(body):
            errors.append(f"internal_error:{pattern.pattern[:40]}")
    return errors


def build_finding(
    url: str,
    severity: str,
    title: str,
    category: str,
    signals: list[str],
    evidence: dict[str, Any],
    explanation: str,
    status_code: int | None = None,
) -> dict[str, Any]:
    """Build a standardized finding dict."""
    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "status_code": status_code,
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": 0.9
        if severity == "critical"
        else 0.8
        if severity == "high"
        else 0.65
        if severity == "medium"
        else 0.5,
        "signals": signals,
        "evidence": evidence,
        "explanation": explanation,
        "score": severity_score(severity),
    }
