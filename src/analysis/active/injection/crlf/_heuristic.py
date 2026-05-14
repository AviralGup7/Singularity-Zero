"""Heuristic pre-scan to skip futile targets."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.passive.runtime import ResponseCache

from ._user_agents import _rotate_user_agent
from ._waf_detector import _detect_waf


def _heuristic_check(
    url: str,
    response_cache: ResponseCache,
    token: str,
) -> dict[str, Any] | None:
    """Send 1-2 quick CRLF probes to determine if full scan is worthwhile.

    Returns a dict with:
      - waf_detected: str | None
      - blocked: bool (WAF blocked the probe entirely)
      - crlf_handled_safely: bool (server handles CRLF safely, no injection)

    If blocked or safely handled, the caller should skip the full scan.
    """
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not query_pairs:
        return None

    param_idx, param_name, param_value = 0, query_pairs[0][0], query_pairs[0][1]
    probe_payload = f"{param_value}%0d%0aX-CRLF-Probe:{token}"
    updated = list(query_pairs)
    updated[param_idx] = (param_name, probe_payload)
    test_url = urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

    ua = _rotate_user_agent()
    response = response_cache.request(
        test_url,
        method="GET",
        headers={
            "User-Agent": ua,
            "Cache-Control": "no-cache",
            "X-CRLF-Heuristic": token,
        },
    )
    if not response:
        return {"waf_detected": None, "blocked": True, "crlf_handled_safely": False}

    status = int(response.get("status_code") or 0)
    resp_headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    body = str(response.get("body_text", "") or "")[:8000]

    waf = _detect_waf(status, resp_headers, body)

    blocked = status == 403 and waf is not None
    crlf_safe = (
        resp_headers.get("x-crlf-probe", "").lower() != token.lower()
        and f"x-crlf-probe:{token.lower()}" not in body.lower()
        and token.lower() not in body.lower()
    )

    return {
        "waf_detected": waf,
        "blocked": blocked,
        "crlf_handled_safely": crlf_safe,
    }
