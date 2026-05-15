"""Helper functions for deserialization probing."""

import base64
import time
from typing import Any

import requests

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    meaningful_query_pairs,
)
from src.analysis.helpers.scoring import severity_score
from src.core.utils.url_validation import is_safe_url

from ._constants import (
    DESERIALIZATION_ERRORS,
    DOTNET_MARKERS,
    DOTNET_PAYLOAD,
    JAVA_MARKERS,
    JAVA_PAYLOAD,
    PHP_MARKERS,
    PHP_PAYLOAD,
    PYTHON_MARKERS,
    PYTHON_PAYLOAD,
    RUBY_MARKERS,
    RUBY_PAYLOAD,
    SERIAL_PARAM_NAMES,
    SERIALIZATION_CONTENT_TYPES,
    SERIALIZATION_PATH_PATTERNS,
    STACK_TRACE_PATTERNS,
    VULNERABLE_INDICATORS,
)


def safe_request(
    url: str,
    method: str = "POST",
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


def detect_serialization_markers(body: str) -> list[str]:
    """Detect serialization framework markers in response body."""
    markers: list[str] = []
    for marker_set, lang_name in [
        (JAVA_MARKERS, "java"),
        (PYTHON_MARKERS, "python"),
        (PHP_MARKERS, "php"),
        (RUBY_MARKERS, "ruby"),
        (DOTNET_MARKERS, "dotnet"),
    ]:
        for pattern in marker_set:
            if pattern.search(body):
                marker = f"serialization_marker:{lang_name}"
                if marker not in markers:
                    markers.append(marker)
                break
    return markers


def detect_deserialization_errors(body: str) -> list[str]:
    """Detect deserialization error messages in response body."""
    errors: list[str] = []
    for pattern in DESERIALIZATION_ERRORS:
        if pattern.search(body):
            errors.append(f"deser_error:{pattern.pattern[:40]}")
    return errors


def detect_vulnerable_response(body: str) -> bool:
    """Check if response indicates successful payload execution."""
    for pattern in VULNERABLE_INDICATORS:
        if pattern.search(body):
            return True
    return False


def detect_stack_traces(body: str) -> list[str]:
    """Detect stack traces in response body."""
    traces: list[str] = []
    for pattern in STACK_TRACE_PATTERNS:
        match = pattern.search(body)
        if match:
            traces.append(f"stack_trace:{pattern.pattern[:40]}")
    return traces


def is_serialization_endpoint(url: str, content_type: str = "") -> bool:
    """Check if URL looks like a serialization endpoint."""
    lowered = url.lower()
    if any(token in lowered for token in SERIALIZATION_PATH_PATTERNS):
        return True
    if content_type:
        ct_lower = content_type.lower()
        if any(token in ct_lower for token in SERIALIZATION_CONTENT_TYPES):
            return True
    return False


def has_serialization_params(url: str) -> list[str]:
    """Check if URL has parameters that might accept serialized data."""
    params: list[str] = []
    pairs = meaningful_query_pairs(url)
    for name, value in pairs:
        if name in SERIAL_PARAM_NAMES:
            params.append(name)
        elif len(value) > 50:
            if any(
                indicator in value[:20]
                for indicator in ("rO0AB", "aced", "O:", "a:", "MARSHAL", "__type")
            ):
                params.append(name)
    return params


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


def get_payloads() -> list[tuple[str, bytes, str]]:
    """Get language-specific deserialization payloads."""
    return [
        ("java", base64.b64decode(JAVA_PAYLOAD), "application/x-java-serialized-object"),
        ("python", PYTHON_PAYLOAD.encode("utf-8", errors="replace"), "application/x-python-pickle"),
        ("php", PHP_PAYLOAD.encode("utf-8"), "application/x-php-serialize"),
        ("ruby", RUBY_PAYLOAD, "application/x-ruby-marshal"),
        ("dotnet", DOTNET_PAYLOAD.encode("utf-8"), "application/json"),
    ]
