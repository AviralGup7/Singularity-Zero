"""Cookie manipulation active probe."""

import base64
import json
import logging
from typing import Any

from src.analysis._core.http_request import _safe_request
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.helpers._probe_utils import probe_confidence, probe_severity
from src.analysis.passive.runtime import ResponseCache

logger = logging.getLogger(__name__)

COOKIE_OVERFLOW_VALUE = "A" * 10000

COOKIE_INJECTION_NAMES = [
    "is_admin",
    "role",
    "user_id",
    "session_id",
    "token",
    "privilege",
    "access_level",
    "permissions",
]


def _parse_cookies(headers: dict[str, Any]) -> list[dict[str, Any]]:
    cookies = []
    set_cookie_values = []
    for key, val in headers.items():
        if key.lower() == "set-cookie":
            if isinstance(val, list):
                set_cookie_values.extend(val)
            else:
                set_cookie_values.append(val)
    for cookie_str in set_cookie_values:
        parts = cookie_str.split(";")
        name_value = parts[0].strip()
        if "=" in name_value:
            name, value = name_value.split("=", 1)
            attrs = {}
            for part in parts[1:]:
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    attrs[k.strip().lower()] = v.strip()
                else:
                    attrs[part.strip().lower()] = True
            cookies.append(
                {"name": name.strip(), "value": value.strip(), "attrs": attrs, "raw": cookie_str}
            )
    return cookies


def _try_base64_decode(value: str) -> bytes | None:
    try:
        padded = value + "=" * (4 - len(value) % 4) if len(value) % 4 else value
        return base64.b64decode(padded)
    except Exception:
        return None


def _try_json_decode(value: str) -> Any | None:
    try:
        return json.loads(value)
    except Exception:
        return None


def cookie_manipulation_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test endpoints for cookie security vulnerabilities.

    Tests cookie tampering, flag removal, prefix testing, session fixation,
    cookie overflow, and cookie injection.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of cookie manipulation findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

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

        original_status = original_resp.get("status", 0)
        original_body = str(original_resp.get("body") or original_resp.get("body_text") or "")
        original_headers = original_resp.get("headers", {})

        cookies = _parse_cookies(original_headers)
        if not cookies:
            existing_cookie = ""
            for key, val in original_headers.items():
                if key.lower() == "cookie":
                    existing_cookie = val
                    break
            if existing_cookie:
                for part in existing_cookie.split(";"):
                    part = part.strip()
                    if "=" in part:
                        name, value = part.split("=", 1)
                        cookies.append(
                            {"name": name.strip(), "value": value.strip(), "attrs": {}, "raw": part}
                        )

        if not cookies:
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for cookie in cookies:
            cookie_name = cookie["name"]
            cookie_value = cookie["value"]
            cookie_attrs = cookie["attrs"]

            if not cookie_attrs.get("secure"):
                url_issues.append("cookie_missing_secure_flag")
                url_probes.append(
                    {
                        "cookie": cookie_name,
                        "test": "missing_secure_flag",
                        "issues": ["cookie_missing_secure_flag"],
                    }
                )

            if not cookie_attrs.get("httponly"):
                url_issues.append("cookie_missing_httponly_flag")
                url_probes.append(
                    {
                        "cookie": cookie_name,
                        "test": "missing_httponly_flag",
                        "issues": ["cookie_missing_httponly_flag"],
                    }
                )

            if not cookie_attrs.get("samesite"):
                url_issues.append("cookie_missing_samesite_flag")
                url_probes.append(
                    {
                        "cookie": cookie_name,
                        "test": "missing_samesite_flag",
                        "issues": ["cookie_missing_samesite_flag"],
                    }
                )
            elif str(cookie_attrs.get("samesite", "")).lower() == "none":
                url_issues.append("cookie_samesite_none")
                url_probes.append(
                    {
                        "cookie": cookie_name,
                        "test": "samesite_none",
                        "issues": ["cookie_samesite_none"],
                    }
                )

            tampered_value = cookie_value + "tampered"
            test_headers = dict(original_headers)
            test_headers["Cookie"] = f"{cookie_name}={tampered_value}"
            response = _safe_request(url, headers=test_headers, timeout=10)
            if response:
                status = response.get("status", 0)
                body = str(response.get("body") or "")
                if status == 200 and original_status in (200, 0):
                    if body and body != original_body[:8000]:
                        url_issues.append("cookie_tampering_accepted")
                        url_probes.append(
                            {
                                "cookie": cookie_name,
                                "test": "value_tampering",
                                "original_value_preview": cookie_value[:50],
                                "tampered_value_preview": tampered_value[:50],
                                "status_code": status,
                                "issues": ["cookie_tampering_accepted"],
                            }
                        )

            decoded = _try_base64_decode(cookie_value)
            if decoded:
                try:
                    decoded_str = decoded.decode("utf-8", errors="replace")
                    modified = (
                        decoded_str.replace("user", "admin")
                        .replace("false", "true")
                        .replace("0", "1")
                    )
                    reencoded = base64.b64encode(modified.encode()).decode()
                    test_headers = dict(original_headers)
                    test_headers["Cookie"] = f"{cookie_name}={reencoded}"
                    response = _safe_request(url, headers=test_headers, timeout=10)
                    if response:
                        status = response.get("status", 0)
                        if status in (200, 302) and original_status in (401, 403):
                            url_issues.append("cookie_base64_tampering_bypass")
                            url_probes.append(
                                {
                                    "cookie": cookie_name,
                                    "test": "base64_tampering",
                                    "status_code": status,
                                    "issues": ["cookie_base64_tampering_bypass"],
                                }
                            )
                        elif status == 200 and original_status in (200, 0):
                            body = str(response.get("body") or "")
                            if "admin" in body.lower() or "true" in body.lower():
                                url_issues.append("cookie_base64_privilege_escalation")
                                url_probes.append(
                                    {
                                        "cookie": cookie_name,
                                        "test": "base64_privilege_escalation",
                                        "status_code": status,
                                        "issues": ["cookie_base64_privilege_escalation"],
                                    }
                                )
                except Exception as exc:
                    logger.warning("Base64 cookie tampering decode failed for %s: %s", url, exc)

            json_val = _try_json_decode(cookie_value)
            if isinstance(json_val, dict):
                modified_json = dict(json_val)
                modified_json["admin"] = True
                modified_json["role"] = "admin"
                modified_json["is_admin"] = True
                modified_json["privilege"] = "elevated"
                reencoded = json.dumps(modified_json)
                test_headers = dict(original_headers)
                test_headers["Cookie"] = f"{cookie_name}={reencoded}"
                response = _safe_request(url, headers=test_headers, timeout=10)
                if response:
                    status = response.get("status", 0)
                    if status in (200, 302) and original_status in (401, 403):
                        url_issues.append("cookie_json_tampering_bypass")
                        url_probes.append(
                            {
                                "cookie": cookie_name,
                                "test": "json_tampering",
                                "status_code": status,
                                "issues": ["cookie_json_tampering_bypass"],
                            }
                        )

            secure_test_headers = dict(original_headers)
            secure_test_headers["Cookie"] = f"{cookie_name}={cookie_value}"
            response = _safe_request(url, headers=secure_test_headers, timeout=10)
            if response:
                resp_cookies = _parse_cookies(response.get("headers", {}))
                for rc in resp_cookies:
                    if rc["name"] == cookie_name:
                        if not rc["attrs"].get("secure"):
                            if "cookie_secure_not_enforced" not in url_issues:
                                url_issues.append("cookie_secure_not_enforced")
                                url_probes.append(
                                    {
                                        "cookie": cookie_name,
                                        "test": "secure_not_enforced",
                                        "issues": ["cookie_secure_not_enforced"],
                                    }
                                )

        overflow_headers = dict(original_headers)
        overflow_headers["Cookie"] = f"overflow_test={COOKIE_OVERFLOW_VALUE}"
        response = _safe_request(url, headers=overflow_headers, timeout=10)
        if response:
            status = response.get("status", 0)
            if status in (500, 502, 503, 413):
                url_issues.append("cookie_overflow_server_error")
                url_probes.append(
                    {
                        "cookie": "overflow_test",
                        "test": "cookie_overflow",
                        "status_code": status,
                        "issues": ["cookie_overflow_server_error"],
                    }
                )
            elif status == 200:
                url_issues.append("cookie_overflow_accepted")
                url_probes.append(
                    {
                        "cookie": "overflow_test",
                        "test": "cookie_overflow",
                        "status_code": status,
                        "issues": ["cookie_overflow_accepted"],
                    }
                )

        for inj_name in COOKIE_INJECTION_NAMES:
            inj_headers = dict(original_headers)
            existing_cookie_header = ""
            for key, val in original_headers.items():
                if key.lower() == "cookie":
                    existing_cookie_header = val
                    break
            inj_headers["Cookie"] = f"{existing_cookie_header}; {inj_name}=admin".strip("; ")
            response = _safe_request(url, headers=inj_headers, timeout=10)
            if response:
                status = response.get("status", 0)
                body = str(response.get("body") or "")
                if status != original_status and status not in (400, 404):
                    url_issues.append(f"cookie_injection_{inj_name}")
                    url_probes.append(
                        {
                            "cookie": inj_name,
                            "test": "cookie_injection",
                            "injected_name": inj_name,
                            "injected_value": "admin",
                            "status_code": status,
                            "original_status": original_status,
                            "issues": [f"cookie_injection_{inj_name}"],
                        }
                    )
                    break

        if url_probes:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": url_issues,
                    "probes": url_probes,
                    "confidence": probe_confidence(url_issues),
                    "severity": probe_severity(url_issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]
