"""Streaming HTTP response utilities for chunked reading.

Provides stream_http_response() for reading HTTP responses in configurable
chunks with enforcement of max_bytes during streaming (not after loading).
"""

import logging
from typing import Any

import urllib3

from src.core.utils.http_pool import get_pooled_connection

logger = logging.getLogger(__name__)

_DEFAULT_CHUNK_SIZE = 8192


def stream_http_response(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    max_bytes: int = 1_048_576,
    timeout: int = 30,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
) -> dict[str, Any]:
    """Fetch an HTTP response and read the body in chunks.

    Reads the response body in ``chunk_size`` byte increments, stopping
    once ``max_bytes`` have been consumed.  This prevents loading large
    responses entirely into memory.

    Args:
        url: Target URL.
        method: HTTP method (default GET).
        headers: Optional request headers.
        max_bytes: Maximum number of body bytes to read.
        timeout: Request timeout in seconds.
        chunk_size: Size of each read chunk in bytes (default 8KB).

    Returns:
        Dict with keys:
            - url: The requested URL.
            - status_code: HTTP status code.
            - headers: Response headers dict.
            - body: Bytes read (may be partial).
            - body_length: Number of bytes in body.
            - truncated: True if the response was cut off at max_bytes.
            - content_type: Content-Type header value.
            - content_length: Content-Length header value (if present).
            - error: Error message if the request failed.
    """
    request_headers = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSecurityTestPipeline/1.0"),
        "Accept": "text/html,application/xhtml+xml,application/json,*/*",
    }
    if headers:
        request_headers.update(headers)

    pool = get_pooled_connection(timeout=float(timeout))
    result: dict[str, Any] = {
        "url": url,
        "status_code": None,
        "headers": {},
        "body": b"",
        "body_length": 0,
        "truncated": False,
        "content_type": "",
        "content_length": None,
        "error": None,
    }

    resp = None
    try:
        resp = pool.request(
            method.upper(),
            url,
            headers=request_headers,
            timeout=urllib3.Timeout(connect=timeout, read=timeout),
            preload_content=False,
            retries=urllib3.Retry(
                total=0,
                redirect=5,
                status_forcelist=[429, 500, 502, 503, 504],
            ),
        )

        result["status_code"] = resp.status
        result["headers"] = dict(resp.headers.items())
        result["content_type"] = resp.headers.get("Content-Type", "")
        content_length_header = resp.headers.get("Content-Length")
        if content_length_header:
            try:
                result["content_length"] = int(content_length_header)
            except (ValueError, TypeError):
                pass

        body_parts: list[bytes] = []
        bytes_read = 0

        try:
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break

                remaining = max_bytes - bytes_read
                if remaining <= 0:
                    result["truncated"] = True
                    break

                if len(chunk) > remaining:
                    body_parts.append(chunk[:remaining])
                    bytes_read += remaining
                    result["truncated"] = True
                else:
                    body_parts.append(chunk)
                    bytes_read += len(chunk)
        finally:
            resp.close()

        result["body"] = b"".join(body_parts)
        result["body_length"] = bytes_read

    except urllib3.exceptions.MaxRetryError as exc:
        logger.error("Max retries exceeded for %s: %s", url, exc)
        result["error"] = f"Max retries: {exc}"
    except urllib3.exceptions.ProtocolError as exc:
        logger.error("Protocol error fetching %s: %s", url, exc)
        result["error"] = f"Protocol error: {exc}"
    except urllib3.exceptions.ReadTimeoutError as exc:
        logger.error("Read timeout fetching %s: %s", url, exc)
        result["error"] = f"Read timeout: {exc}"
    except Exception as exc:
        logger.error("Unexpected error fetching %s: %s", url, exc)
        result["error"] = str(exc)
    finally:
        if resp is not None:
            try:
                resp.release_conn()
            except Exception:  # noqa: S110
                pass  # Connection release best-effort

    return result


__all__ = ["stream_http_response"]
