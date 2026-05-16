"""Consolidated HTTP utilities for safe, performant requests.

Provides both synchronous (requests) and asynchronous (httpx) versions of
'safe_request', which implements SSRF protection, timeout enforcement,
and standardized response normalization.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import requests

from src.core.frontier.chameleon import wrap_polymorphic_request
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.utils.url_validation import is_safe_url

logger = get_pipeline_logger(__name__)

DEFAULT_TIMEOUT = 10.0
MAX_BODY_LENGTH = 120_000
_SYNC_SESSION = requests.Session()
_ASYNC_CLIENTS: dict[tuple[bool, bool], httpx.AsyncClient] = {}


def _get_async_client(verify_ssl: bool, follow_redirects: bool) -> httpx.AsyncClient:
    client_key = (verify_ssl, follow_redirects)
    client = _ASYNC_CLIENTS.get(client_key)
    if client is None:
        client = httpx.AsyncClient(verify=verify_ssl, follow_redirects=follow_redirects)
        _ASYNC_CLIENTS[client_key] = client
    return client


def safe_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float | None = None,
    max_body_length: int = MAX_BODY_LENGTH,
    verify_ssl: bool | None = None,
) -> dict[str, Any]:
    """Synchronous safe request with SSRF protection.

    Args:
        url: Target URL.
        method: HTTP method.
        headers: Optional headers.
        body: Optional request body.
        timeout: Timeout in seconds.
        max_body_length: Max body size to read.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        Standardized response dictionary.
    """
    if not is_safe_url(url):
        return _error_response("URL failed safety check", url=url)

    # Fix Audit #10: Use Polymorphic Chameleon instead of hardcoded User-Agent
    request_headers = dict(headers or {})
    chameleon_config = wrap_polymorphic_request(request_headers)
    req_headers = chameleon_config["headers"]
    req_headers.setdefault("Accept", "application/json, text/html, */*")

    # Use Chameleon's verify and timeout unless the caller explicitly overrides them.
    final_verify = chameleon_config.get("verify", True) if verify_ssl is None else verify_ssl
    final_timeout = chameleon_config.get("timeout", DEFAULT_TIMEOUT) if timeout is None else timeout

    try:
        start_time = time.monotonic()
        resp = _SYNC_SESSION.request(
            method=method,
            url=url,
            headers=req_headers,
            data=body,
            timeout=final_timeout,
            verify=final_verify,
        )
        duration_ms = (time.monotonic() - start_time) * 1000

        resp_body = resp.text or ""
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp_body[:max_body_length],
            "body_length": len(resp_body),
            "duration_ms": round(duration_ms, 2),
            "success": resp.status_code < 400,
            "url": url,
        }
    except requests.RequestException as e:
        return _error_response(str(e), url=url, exc=e)
    except Exception as e:
        return _error_response(str(e), url=url, exc=e)


async def async_safe_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float | None = None,
    max_body_length: int = MAX_BODY_LENGTH,
    verify_ssl: bool | None = None,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    """Asynchronous safe request with SSRF protection using httpx.

    Args:
        url: Target URL.
        method: HTTP method.
        headers: Optional headers.
        body: Optional request body.
        timeout: Timeout in seconds.
        max_body_length: Max body size to read.
        verify_ssl: Whether to verify SSL certificates.
        follow_redirects: Whether to follow HTTP redirects.

    Returns:
        Standardized response dictionary.
    """
    if not is_safe_url(url):
        return _error_response("URL failed safety check", url=url)

    # Fix Audit #10: Use Polymorphic Chameleon
    request_headers = dict(headers or {})
    chameleon_config = wrap_polymorphic_request(request_headers)
    req_headers = chameleon_config["headers"]
    req_headers.setdefault("Accept", "application/json, text/html, */*")

    final_verify = chameleon_config.get("verify", True) if verify_ssl is None else verify_ssl
    final_timeout = chameleon_config.get("timeout", DEFAULT_TIMEOUT) if timeout is None else timeout
    final_follow = follow_redirects # Chameleon might provide this too but we prefer the explicit param

    try:
        start_time = time.monotonic()
        client = _get_async_client(final_verify, final_follow)
        resp = await client.request(
            method=method,
            url=url,
            headers=req_headers,
            content=body,
            timeout=final_timeout,
        )
        duration_ms = (time.monotonic() - start_time) * 1000

        resp_body = resp.text or ""
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp_body[:max_body_length],
            "body_length": len(resp_body),
            "duration_ms": round(duration_ms, 2),
            "success": resp.status_code < 400,
            "url": url,
        }
    except httpx.HTTPError as e:
        return _error_response(str(e), url=url, exc=e)
    except Exception as e:
        return _error_response(str(e), url=url, exc=e)


def _error_response(error: str, url: str = "", exc: Exception | None = None) -> dict[str, Any]:
    """Build a standardized error response."""
    status = 0
    headers = {}
    if exc and hasattr(exc, "response") and exc.response is not None:
        try:
            status = getattr(exc.response, "status_code", 0)
            headers = dict(getattr(exc.response, "headers", {}))
        except Exception:  # noqa: S110
            pass

    return {
        "status": status,
        "headers": headers,
        "body": "",
        "body_length": 0,
        "duration_ms": 0.0,
        "success": False,
        "error": error,
        "url": url,
    }
