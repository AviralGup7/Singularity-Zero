"""Session fixation attacks via cookie manipulation."""

import logging
import time
from typing import Any

from src.analysis._core.http_request import _safe_request
from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
)
from src.analysis.passive.runtime import ResponseCache

from .auth_bypass_utils import (
    _has_auth_indicator,
    _to_str_body,
    probe_confidence_from_auth_bypass_map,
    probe_severity_from_auth_bypass_map,
)

logger = logging.getLogger(__name__)

_RATE_LIMIT_DELAY = 0.05


def probe_session_fixation(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Manipulate session cookies and test for fixation vulnerabilities.

    For each URL with existing cookies, tests:
    - Empty cookie value
    - Deleted cookie (removed entirely)
    - Modified cookie (appended tamper string)
    - Session fixation (replacing session ID with a known value)

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of cookie manipulation findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    _last_request_time = 0.0

    session_cookie_names = {
        "session",
        "session_id",
        "sid",
        "sess",
        "phpsessid",
        "jsessionid",
        "connect.sid",
        "express:sess",
        "aspsessionid",
        "asp.net_sessionid",
    }

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        original_resp = response_cache.get(url)
        if not original_resp:
            original_resp = _safe_request(url, timeout=8)
        if not original_resp or original_resp.get("status") in (404, 410, 503):
            continue

        original_status = int(original_resp.get("status", 0))
        original_headers = original_resp.get("headers", {})
        original_body = _to_str_body(original_resp.get("body") or original_resp.get("body_text"))

        existing_cookie = ""
        for key, val in original_headers.items():
            if key.lower() == "cookie":
                existing_cookie = val
                break
        if not existing_cookie:
            continue

        cookie_parts = [p.strip() for p in existing_cookie.split(";") if "=" in p]
        if not cookie_parts:
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        stripped_headers_base = {
            k: (str(v) if not isinstance(v, str) else v)
            for k, v in original_headers.items()
            if k.lower() not in ("cookie",)
        }

        try:
            for part in cookie_parts:
                name, value = part.split("=", 1)
                name = name.strip()
                value = value.strip()

                tampered_headers = dict(stripped_headers_base)
                tampered_headers["Cookie"] = f"{name}={value}tampered"
                logger.debug("Probing cookie tampering on %s for %s", url, name)
                now = time.time()
                elapsed = now - _last_request_time
                if elapsed < _RATE_LIMIT_DELAY:
                    time.sleep(_RATE_LIMIT_DELAY - elapsed)
                response = _safe_request(url, headers=tampered_headers, timeout=10)
                _last_request_time = time.time()
                if response:
                    status = int(response.get("status", 0))
                    body = _to_str_body(response.get("body") or "")
                    if status == 200 and original_status in (401, 403):
                        if "cookie_modified_bypass" not in url_issues:
                            url_issues.append("cookie_modified_bypass")
                        url_probes.append(
                            {
                                "cookie": name,
                                "test": "modified_value",
                                "original_status": original_status,
                                "modified_status": status,
                            }
                        )
                    elif (
                        status == 200 and original_status in (200,) and body != original_body[:8000]
                    ):
                        if "cookie_modified_accepted" not in url_issues:
                            url_issues.append("cookie_modified_accepted")
                        url_probes.append(
                            {
                                "cookie": name,
                                "test": "modified_value",
                                "status": status,
                            }
                        )

                empty_headers = dict(stripped_headers_base)
                empty_headers["Cookie"] = f"{name}="
                logger.debug("Probing empty cookie on %s for %s", url, name)
                now = time.time()
                elapsed = now - _last_request_time
                if elapsed < _RATE_LIMIT_DELAY:
                    time.sleep(_RATE_LIMIT_DELAY - elapsed)
                response = _safe_request(url, headers=empty_headers, timeout=10)
                _last_request_time = time.time()
                if response:
                    status = int(response.get("status", 0))
                    if status == 200 and original_status in (401, 403):
                        url_issues.append("cookie_empty_bypass")
                        url_probes.append(
                            {
                                "cookie": name,
                                "test": "empty_value",
                                "original_status": original_status,
                                "empty_status": status,
                            }
                        )

                deleted_headers = dict(stripped_headers_base)
                logger.debug("Probing deleted cookie on %s for %s", url, name)
                now = time.time()
                elapsed = now - _last_request_time
                if elapsed < _RATE_LIMIT_DELAY:
                    time.sleep(_RATE_LIMIT_DELAY - elapsed)
                response = _safe_request(url, headers=deleted_headers, timeout=10)
                _last_request_time = time.time()
                if response:
                    status = int(response.get("status", 0))
                    body = _to_str_body(response.get("body") or "")
                    if status == 200 and original_status in (401, 403):
                        url_issues.append("cookie_deleted_bypass")
                        url_probes.append(
                            {
                                "cookie": name,
                                "test": "deleted_cookie",
                                "original_status": original_status,
                                "deleted_status": status,
                            }
                        )
                    elif (
                        status == 200
                        and original_status in (200,)
                        and _has_auth_indicator(response.get("headers", {}), body)
                    ):
                        if "cookie_deleted_auth_still_valid" not in url_issues:
                            url_issues.append("cookie_deleted_auth_still_valid")
                        url_probes.append(
                            {
                                "cookie": name,
                                "test": "deleted_cookie_auth_valid",
                                "status": status,
                            }
                        )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cookie manipulation failed for %s: %s", url, exc)

        try:
            for part in cookie_parts:
                name = part.split("=", 1)[0].strip()
                if name.lower() in session_cookie_names:
                    fixation_headers = dict(stripped_headers_base)
                    fixation_headers["Cookie"] = f"{name}=fixation_test_12345"
                    logger.debug("Probing session fixation on %s for %s", url, name)
                    now = time.time()
                    elapsed = now - _last_request_time
                    if elapsed < _RATE_LIMIT_DELAY:
                        time.sleep(_RATE_LIMIT_DELAY - elapsed)
                    response = _safe_request(url, headers=fixation_headers, timeout=10)
                    _last_request_time = time.time()
                    if response:
                        status = int(response.get("status", 0))
                        body = _to_str_body(response.get("body") or "")
                        if (
                            status == 200
                            and original_status in (200,)
                            and body != original_body[:8000]
                        ):
                            url_issues.append("cookie_fixation_indicator")
                            url_probes.append(
                                {
                                    "cookie": name,
                                    "test": "session_fixation",
                                    "status": status,
                                }
                            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Session fixation probe failed for %s: %s", url, exc)

        if url_probes:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": url_issues,
                    "probe_type": "cookie_manipulation",
                    "probes": url_probes,
                    "confidence": probe_confidence_from_auth_bypass_map(url_issues),
                    "severity": probe_severity_from_auth_bypass_map(url_issues),
                }
            )

        time.sleep(0.01)

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]


probe_cookie_manipulation = probe_session_fixation
