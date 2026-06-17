"""Self-contained HTTP fetch for validation probes.

Provides ``fetch_response_once`` and ``build_response_record`` without
depending on the analysis layer, so that execution-layer modules can
import them without violating the execution -> analysis contract.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import urllib3

from src.core.models import DEFAULT_USER_AGENT
from src.core.utils import normalize_url
from src.core.utils.url_validation import is_safe_url

# Shared pool for connection reuse
_HTTP_POOL = urllib3.PoolManager(
    num_pools=50,
    maxsize=10,
    block=False,
    retries=False,
    timeout=urllib3.util.Timeout(connect=10, read=10),
)

_TEXTUAL_CONTENT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/xhtml",
    "application/javascript",
    "application/x-javascript",
)


@dataclass(frozen=True)
class FetchResponseResult:
    record: dict[str, Any] | None
    latency_seconds: float
    status_code: int | None
    successful: bool
    retryable: bool


def is_textual_content_type(content_type: str) -> bool:
    normalized = content_type.lower()
    return any(normalized.startswith(prefix) for prefix in _TEXTUAL_CONTENT_TYPES)


def extract_charset(content_type: str) -> str:
    if "charset=" not in content_type.lower():
        return "utf-8"
    return content_type.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"


def build_response_record(
    url: str, response: Any, max_bytes: int, *, request_method: str = "GET", latency_ms: float = 0.0
) -> dict[str, Any]:
    headers = dict(response.headers.items())
    content_type = headers.get("Content-Type", "")
    body_text: str | None = ""
    raw = b""
    if max_bytes > 0:
        if getattr(response, "data", None):
            raw = response.data
        else:
            raw = response.read(max_bytes + 1)
    if is_textual_content_type(content_type) and raw:
        charset = extract_charset(content_type)
        try:
            body_text = raw[:max_bytes].decode(charset, errors="replace")
        except LookupError:
            try:
                body_text = raw[:max_bytes].decode("utf-8", errors="replace")
            except Exception:
                body_text = raw[:max_bytes].decode("latin-1", errors="replace")
    else:
        body_text = None

    status_code = getattr(response, "status", None) or getattr(response, "code", None)
    final_url = normalize_url(getattr(response, "geturl", lambda: url)() or url)
    return {
        "requested_url": normalize_url(url),
        "request_method": request_method,
        "url": final_url,
        "final_url": final_url,
        "status_code": status_code,
        "headers": headers,
        "content_type": content_type,
        "body_text": body_text,
        "body_length": len(body_text) if body_text is not None else 0,
        "truncated": len(raw) > max_bytes if max_bytes > 0 else False,
        "redirect_chain": [normalize_url(url), final_url]
        if final_url != normalize_url(url)
        else [normalize_url(url)],
        "redirect_count": 1 if final_url != normalize_url(url) else 0,
        "response_time_ms": round(latency_ms, 2),
    }


def fetch_response_once(
    url: str,
    timeout_seconds: int,
    max_bytes: int,
    *,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
) -> FetchResponseResult:
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*",
    }
    if extra_headers:
        headers.update(extra_headers)

    request_body: bytes | None = body.encode("utf-8") if isinstance(body, str) else body
    if request_body and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"

    if not is_safe_url(url):
        return FetchResponseResult(None, 0.0, None, False, False)

    started_at = time.monotonic()
    try:
        response = _HTTP_POOL.request(
            method.upper(),
            url,
            headers=headers,
            body=request_body,
            preload_content=True,
            timeout=urllib3.util.Timeout(connect=timeout_seconds, read=timeout_seconds),
        )

        latency = time.monotonic() - started_at
        record = build_response_record(
            url, response, max_bytes, request_method=method.upper(), latency_ms=latency * 1000
        )

        status_code = int(record.get("status_code") or 0)
        successful = status_code < 400
        retryable = status_code == 429 or 500 <= status_code < 600

        return FetchResponseResult(
            record=record,
            latency_seconds=latency,
            status_code=status_code,
            successful=successful,
            retryable=retryable,
        )
    except urllib3.exceptions.HTTPError:
        return FetchResponseResult(None, time.monotonic() - started_at, None, False, True)
    except Exception:
        raise
