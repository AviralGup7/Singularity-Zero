"""Helper functions for XML bomb detection."""

import time
from typing import Any

import requests

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.utils.url_validation import is_safe_url

from ._constants import (
    XML_BOMB_PAYLOADS,
    XML_CONTENT_TYPES,
    XML_DECLARATION_RE,
    XML_EXTENSIONS,
    XML_PATH_HINTS,
)


def safe_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Make a safe HTTP request and return response info."""
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
            "elapsed": 0.0,
            "error": "URL failed safety check",
        }
    start_time = time.monotonic()
    try:
        resp = requests.request(
            method, url, headers=req_headers, data=body, timeout=timeout, verify=True
        )
        elapsed = time.monotonic() - start_time
        resp_body = resp.text or ""
        return {
            "status": getattr(resp, "status_code", 0),
            "headers": dict(resp.headers),
            "body": (resp_body or "")[:5000],
            "success": resp.status_code < 400,
            "elapsed": elapsed,
        }
    except requests.RequestException as e:
        elapsed = time.monotonic() - start_time
        resp_obj = getattr(e, "response", None)
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
            "elapsed": elapsed,
            "error": str(e),
        }
    except Exception as e:
        elapsed = time.monotonic() - start_time
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "success": False,
            "elapsed": elapsed,
            "error": str(e),
        }


def normalize_headers(raw_headers: dict[str, Any] | None) -> dict[str, str]:
    """Normalize response headers to lowercase keys with string values."""
    if not raw_headers:
        return {}
    return {str(k).lower(): str(v) for k, v in raw_headers.items()}


def severity_score(severity: str) -> int:
    """Map a severity string to a numeric score."""
    mapping = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 10,
    }
    return mapping.get(severity.lower(), 10)


def compute_confidence(issues: list[str]) -> float:
    """Compute confidence score from detected issues."""
    if not issues:
        return 0.3
    confidence_map = {
        "xxe_file_read_confirmed": 0.95,
        "xxe_windows_file_read": 0.93,
        "xxe_php_filter_read": 0.90,
        "xml_bomb_timeout": 0.88,
        "xml_bomb_error": 0.85,
        "xxe_external_dtd_fetch": 0.82,
        "xxe_error_parser_detail": 0.75,
        "xml_processing_surface": 0.60,
        "xml_entity_expansion_hint": 0.70,
        "quadratic_blowup_accepted": 0.78,
        "xml_parser_disclosure": 0.65,
    }
    max_conf = max((confidence_map.get(issue, 0.4) for issue in issues), default=0.3)
    bonus = min(0.05, len(issues) * 0.01)
    return round(min(max_conf + bonus, 0.98), 2)


def determine_severity(issues: list[str]) -> str:
    """Determine the highest severity from detected issues."""
    severity_map = {
        "xxe_file_read_confirmed": "critical",
        "xxe_windows_file_read": "critical",
        "xxe_php_filter_read": "critical",
        "xml_bomb_timeout": "high",
        "xml_bomb_error": "high",
        "xxe_external_dtd_fetch": "high",
        "xxe_error_parser_detail": "medium",
        "xml_processing_surface": "low",
        "xml_entity_expansion_hint": "medium",
        "quadratic_blowup_accepted": "high",
        "xml_parser_disclosure": "medium",
    }
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    if not issues:
        return "low"
    return max(
        issues,
        key=lambda i: severity_order.get(severity_map.get(i, "low"), 0),
    )


def is_xml_endpoint(url: str, response_body: str = "", content_type: str = "") -> bool:
    """Determine if a URL is likely an XML-processing endpoint."""
    lowered_url = url.lower()
    lowered_ct = content_type.lower()

    if any(lowered_url.endswith(ext) for ext in XML_EXTENSIONS):
        return True

    if any(token in lowered_url for token in XML_PATH_HINTS):
        return True

    if any(ct in lowered_ct for ct in XML_CONTENT_TYPES):
        return True

    if response_body and XML_DECLARATION_RE.search(response_body[:2000]):
        return True

    return False


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
        "confidence": compute_confidence(signals),
        "signals": signals,
        "evidence": evidence,
        "explanation": explanation,
        "score": severity_score(severity),
    }


def get_xml_bomb_payloads() -> list[tuple[str, str]]:
    """Get XML bomb and XXE payloads for testing."""
    return XML_BOMB_PAYLOADS
