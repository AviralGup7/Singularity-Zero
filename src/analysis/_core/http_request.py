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
    from urllib.parse import urlparse

    from src.core.frontier.chameleon import _chameleon, wrap_polymorphic_request

    req_headers = dict(headers or {})
    chameleon_config = wrap_polymorphic_request(req_headers)
    req_headers = chameleon_config["headers"]
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
        parsed = urlparse(url)
        target = parsed.netloc or parsed.path.split("/")[0] or "unknown"
    except Exception:
        target = "unknown"

    session_id = req_headers.get("X-Session-Token") or req_headers.get("X-Trace-ID") or "default"

    try:
        resp = requests.request(
            method,
            url,
            headers=req_headers,
            data=body,
            timeout=chameleon_config.get("timeout", timeout),
            verify=chameleon_config.get("verify", True),
        )
        resp_body = resp.text or ""
        resp_headers = dict(resp.headers)

        # Telemetry / feedback loop update
        detected_waf = None
        try:
            cookies = None
            if hasattr(resp, "cookies") and resp.cookies is not None:
                if hasattr(resp.cookies, "items"):
                    cookies = {str(k): str(v) for k, v in resp.cookies.items()}
                else:
                    try:
                        cookies = {str(c.name): str(c.value) for c in resp.cookies}
                    except Exception:  # noqa: S110
                        cookies = {}
            detected_waf = _chameleon.detect_waf(resp_headers, resp_body, cookies)
            _chameleon._evasion_engine.update_observation(
                response_status=resp.status_code,
                body=resp_body,
                session_id=session_id,
                target=target,
                detected_waf=detected_waf,
            )
        except Exception:  # noqa: S110
            pass

        return {
            "status": getattr(resp, "status_code", 0),
            "headers": resp_headers,
            "body": resp_body[:max_body_length],
            "body_length": len(resp_body),
            "success": resp.status_code < 400,
            "detected_waf": detected_waf,
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
