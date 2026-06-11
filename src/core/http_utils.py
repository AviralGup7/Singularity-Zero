"""Consolidated HTTP utilities for safe, performant requests.

Provides both synchronous (requests) and asynchronous (httpx) versions of
'safe_request', which implements SSRF protection, timeout enforcement,
and standardized response normalization.
"""

from __future__ import annotations

import asyncio
import atexit
import threading
import time
import weakref
from typing import Any

import httpx
import requests

from src.core.frontier.chameleon import wrap_polymorphic_request
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.pid_limiter import PIDRateLimiter
from src.core.utils.url_validation import is_safe_url

logger = get_pipeline_logger(__name__)

_PID_LIMITERS: dict[str, PIDRateLimiter] = {}
_PID_LIMITERS_MAX = 1024

DEFAULT_TIMEOUT = 10.0
MAX_BODY_LENGTH = 120_000
_sync_session_local = threading.local()


def _get_sync_session() -> requests.Session:
    """Return a thread-local requests.Session instance."""
    session = getattr(_sync_session_local, "session", None)
    if session is None:
        session = requests.Session()
        _sync_session_local.session = session
        atexit.register(session.close)
    return session


_ASYNC_CLIENTS: dict[tuple[bool, bool], httpx.AsyncClient] = {}

_ASYNC_CLIENTS_WEAKSET: weakref.WeakSet[httpx.AsyncClient] = weakref.WeakSet()


def _cleanup_async_clients() -> None:
    """Synchronously close all cached async clients at process exit."""
    for client in list(_ASYNC_CLIENTS.values()):
        try:
            if not client.is_closed:
                try:
                    coro = client.aclose()
                except (AttributeError, TypeError):
                    client.close()  # type: ignore[attr-defined]
                else:
                    try:
                        loop = asyncio.get_event_loop()
                        if not loop.is_closed():
                            loop.run_until_complete(coro)
                    except RuntimeError:
                        pass
        except Exception as exc:
            logger.debug("Failed to close httpx client during atexit: %s", exc)
    _ASYNC_CLIENTS.clear()


atexit.register(_cleanup_async_clients)

# Hook httpx.AsyncClient creation to track all instances process-wide
_original_async_client_init = httpx.AsyncClient.__init__


def _patched_async_client_init(self: httpx.AsyncClient, *args: Any, **kwargs: Any) -> None:
    _original_async_client_init(self, *args, **kwargs)
    _ASYNC_CLIENTS_WEAKSET.add(self)


httpx.AsyncClient.__init__ = _patched_async_client_init  # type: ignore[method-assign]


def _get_async_client(verify_ssl: bool, follow_redirects: bool) -> httpx.AsyncClient:
    client_key = (verify_ssl, follow_redirects)
    client = _ASYNC_CLIENTS.get(client_key)
    if client is None:
        client = httpx.AsyncClient(verify=verify_ssl, follow_redirects=follow_redirects)
        _ASYNC_CLIENTS[client_key] = client
    return client


async def close_all_clients() -> None:
    """Acquire all tracked HTTP clients process-wide and cleanly close them."""
    for client in list(_ASYNC_CLIENTS_WEAKSET):
        try:
            if not client.is_closed:
                await client.aclose()
        except Exception as e:
            logger.debug("Failed to close tracked httpx client during shutdown: %s", e)
    _ASYNC_CLIENTS.clear()
    _ASYNC_CLIENTS_WEAKSET.clear()


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
        from urllib.parse import urlparse

        parsed = urlparse(url)
        target = parsed.netloc or parsed.path.split("/")[0] or "unknown"
    except Exception as exc:
        logger.debug("Failed to parse URL %s: %s", url, exc)
        target = "unknown"

    input_headers_lower = {k.lower(): v for k, v in (headers or {}).items()}
    session_id = (
        input_headers_lower.get("x-session-token")
        or input_headers_lower.get("x-trace-id")
        or "default"
    )

    if target not in _PID_LIMITERS:
        if len(_PID_LIMITERS) >= _PID_LIMITERS_MAX:
            _PID_LIMITERS.pop(next(iter(_PID_LIMITERS)))
        _PID_LIMITERS[target] = PIDRateLimiter()
    limiter = _PID_LIMITERS[target]
    if limiter.current_delay > 0.0:
        time.sleep(limiter.current_delay)

    try:
        start_time = time.monotonic()
        resp = _get_sync_session().request(
            method=method,
            url=url,
            headers=req_headers,
            data=body,
            timeout=final_timeout,
            verify=final_verify,
        )
        duration_ms = (time.monotonic() - start_time) * 1000
        is_blocked = resp.status_code in {429, 503}
        limiter.update(duration_ms / 1000.0, is_blocked=is_blocked)

        resp_body = resp.text or ""
        resp_headers = dict(resp.headers)

        # Real-time evasion telemetry update
        detected_waf = None
        try:
            from src.core.frontier.chameleon import _chameleon

            cookies = None
            if hasattr(resp, "cookies") and resp.cookies is not None:
                if hasattr(resp.cookies, "items"):
                    cookies = {str(k): str(v) for k, v in resp.cookies.items()}
                else:
                    try:
                        cookies = {str(c.name): str(c.value) for c in resp.cookies}
                    except Exception as exc:
                        logger.debug("Failed to extract cookies: %s", exc)
                        cookies = {}
            detected_waf = _chameleon.detect_waf(resp_headers, resp_body, cookies)
            _chameleon._evasion_engine.update_observation(
                response_status=resp.status_code,
                body=resp_body,
                session_id=session_id,
                target=target,
                detected_waf=detected_waf,
            )
        except Exception as te:
            logger.debug("Telemetry/Evasion observation feed failed: %s", te)

        return {
            "status": resp.status_code,
            "headers": resp_headers,
            "body": resp_body[:max_body_length],
            "body_length": len(resp_body),
            "duration_ms": round(duration_ms, 2),
            "success": resp.status_code < 400,
            "url": url,
            "detected_waf": detected_waf,
        }
    except requests.ConnectionError as e:
        logger.debug("Connection error for %s: %s", url, e)
        return _error_response(str(e), url=url)
    except requests.Timeout as e:
        logger.debug("Timeout for %s: %s", url, e)
        return _error_response(str(e), url=url)
    except requests.RequestException as e:
        # Feed error as potentially a WAF block / failure
        err_status = 0
        if hasattr(e, "response") and e.response is not None:
            try:
                err_status = getattr(e.response, "status_code", 0)
            except Exception as exc:
                logger.debug("Failed to extract error status: %s", exc)
                logger.warning("Operation failed in http_utils.py: %s", exc, exc_info=True)  # noqa: BLE001
        is_blocked = err_status in {429, 503}
        limiter.update(0.0, is_blocked=is_blocked)

        try:
            from src.core.frontier.chameleon import _chameleon

            # Check if there is an error response we can extract
            err_body = ""
            if hasattr(e, "response") and e.response is not None:
                err_body = getattr(e.response, "text", "")

            _chameleon._evasion_engine.update_observation(
                response_status=err_status or 403,  # default to WAF block / generic failure
                body=err_body,
                session_id=session_id,
                target=target,
                detected_waf=None,
            )
        except Exception as exc:
            logger.debug("Telemetry/Evasion observation failed: %s", exc)
            logger.warning("Operation failed in http_utils.py: %s", exc, exc_info=True)  # noqa: BLE001
        return _error_response(str(e), url=url)
    except Exception as e:
        return _error_response(str(e), url=url)


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
    final_follow = (
        follow_redirects  # Chameleon might provide this too but we prefer the explicit param
    )

    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        target = parsed.netloc or parsed.path.split("/")[0] or "unknown"
    except Exception as exc:
        logger.debug("Failed to parse URL %s: %s", url, exc)
        target = "unknown"

    input_headers_lower = {k.lower(): v for k, v in (headers or {}).items()}
    session_id = (
        input_headers_lower.get("x-session-token")
        or input_headers_lower.get("x-trace-id")
        or "default"
    )

    if target not in _PID_LIMITERS:
        if len(_PID_LIMITERS) >= _PID_LIMITERS_MAX:
            _PID_LIMITERS.pop(next(iter(_PID_LIMITERS)))
        _PID_LIMITERS[target] = PIDRateLimiter()
    limiter = _PID_LIMITERS[target]
    if limiter.current_delay > 0.0:
        await asyncio.sleep(limiter.current_delay)

    try:
        start_time = time.monotonic()
        client = _get_async_client(final_verify, final_follow)
        resp = await client.request(
            method=method,
            url=url,
            headers=req_headers,
            content=body,
            timeout=final_timeout,
            follow_redirects=final_follow,
        )
        duration_ms = (time.monotonic() - start_time) * 1000
        is_blocked = resp.status_code in {429, 503}
        limiter.update(duration_ms / 1000.0, is_blocked=is_blocked)

        resp_body = resp.text or ""
        resp_headers = dict(resp.headers)

        # Real-time evasion telemetry update
        detected_waf = None
        try:
            from src.core.frontier.chameleon import _chameleon

            cookies = None
            if hasattr(resp, "cookies") and resp.cookies is not None:
                if hasattr(resp.cookies, "items"):
                    cookies = {str(k): str(v) for k, v in resp.cookies.items()}
                else:
                    try:
                        cookies = {str(c.name): str(c.value) for c in resp.cookies}  # type: ignore[attr-defined]
                    except Exception as exc:
                        logger.debug("Failed to extract cookies: %s", exc)
                        cookies = {}
            detected_waf = _chameleon.detect_waf(resp_headers, resp_body, cookies)
            _chameleon._evasion_engine.update_observation(
                response_status=resp.status_code,
                body=resp_body,
                session_id=session_id,
                target=target,
                detected_waf=detected_waf,
            )
        except Exception as te:
            logger.debug("Telemetry/Evasion observation feed failed: %s", te)

        return {
            "status": resp.status_code,
            "headers": resp_headers,
            "body": resp_body[:max_body_length],
            "body_length": len(resp_body),
            "duration_ms": round(duration_ms, 2),
            "success": resp.status_code < 400,
            "url": url,
            "detected_waf": detected_waf,
        }
    except httpx.ConnectError as e:
        logger.debug("Connection error for %s: %s", url, e)
        return _error_response(str(e), url=url)
    except httpx.TimeoutException as e:
        logger.debug("Timeout for %s: %s", url, e)
        return _error_response(str(e), url=url)
    except httpx.HTTPStatusError as e:
        logger.debug("HTTP status error for %s: %s", url, e)
        return _error_response(str(e), url=url)
    except httpx.HTTPError as e:
        # Feed error as potentially a WAF block / failure
        err_status = 0
        if hasattr(e, "response") and e.response is not None:
            try:
                err_status = getattr(e.response, "status_code", 0)
            except Exception as exc:
                logger.debug("Failed to extract error status: %s", exc)
                logger.warning("Operation failed in http_utils.py: %s", exc, exc_info=True)  # noqa: BLE001
        is_blocked = err_status in {429, 503}
        limiter.update(0.0, is_blocked=is_blocked)

        try:
            from src.core.frontier.chameleon import _chameleon

            err_body = ""
            if hasattr(e, "response") and e.response is not None:
                err_body = getattr(e.response, "text", "")

            _chameleon._evasion_engine.update_observation(
                response_status=err_status or 403,
                body=err_body,
                session_id=session_id,
                target=target,
                detected_waf=None,
            )
        except Exception as exc:
            logger.debug("Telemetry/Evasion observation failed: %s", exc)
            logger.warning("Operation failed in http_utils.py: %s", exc, exc_info=True)  # noqa: BLE001
        return _error_response(str(e), url=url)
    except Exception as e:
        return _error_response(str(e), url=url)


def _error_response(error: str, url: str = "", exc: Exception | None = None) -> dict[str, Any]:
    """Build a standardized error response."""
    status = 0
    headers = {}
    if exc and hasattr(exc, "response") and exc.response is not None:
        try:
            status = getattr(exc.response, "status_code", 0)
            headers = dict(getattr(exc.response, "headers", {}))
        except Exception as exc:
            logger.debug("Telemetry/Evasion observation failed: %s", exc)
            logger.warning("Operation failed in http_utils.py: %s", exc, exc_info=True)  # noqa: BLE001

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
