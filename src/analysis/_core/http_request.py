"""Shared HTTP request utilities for active probes."""

from typing import Any

import requests

from src.core.utils.url_validation import is_safe_url


def _safe_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 10,
    max_body_length: int = 8000,
) -> dict[str, Any]:
    """Send a safe HTTP request and return a normalized response dict.

    Args:
        url: Target URL.
        method: HTTP method (GET, POST, etc.).
        headers: Optional request headers.
        body: Optional request body as bytes.
        timeout: Request timeout in seconds.
        max_body_length: Maximum response body length to capture.

    Returns:
        Dict with keys: status, headers, body, body_length, success, error (optional).
    """
    req_headers = dict(headers or {})
    req_headers.setdefault(
        "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityPipeline/1.0"
    )
    req_headers.setdefault("Accept", "application/json, text/html, */*")

    if not is_safe_url(url):
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "success": False,
            "error": "URL failed safety check",
        }

    try:
        resp = requests.request(
            method, url, headers=req_headers, data=body, timeout=timeout, verify=True
        )
        resp_body = resp.text or ""
        return {
            "status": getattr(resp, "status_code", 0),
            "headers": dict(resp.headers),
            "body": resp_body[:max_body_length],
            "body_length": len(resp_body),
            "success": resp.status_code < 400,
        }
    except requests.RequestException as e:
        resp_body = ""
        resp_obj = getattr(e, "response", None)
        status = 0
        resp_headers = {}
        if resp_obj is not None:
            try:
                resp_body = resp_obj.text
                status = getattr(resp_obj, "status_code", 0)
                resp_headers = dict(resp_obj.headers)
            except Exception:  # noqa: S110
                pass
        return {
            "status": status,
            "headers": resp_headers,
            "body": (resp_body or "")[:max_body_length],
            "body_length": len(resp_body or ""),
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "success": False,
            "error": str(e),
        }
