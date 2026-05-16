"""HTTP utilities for tenant isolation testing."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from src.recon.common import normalize_url


def _safe_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    req_headers = dict(headers or {})
    req_headers.setdefault(
        "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityPipeline/1.0"
    )
    req_headers.setdefault("Accept", "*/*")
    try:
        resp = requests.request(
            method, url, headers=req_headers, data=body, timeout=timeout, verify=True
        )
        resp_body = resp.text or ""
        return {
            "status": getattr(resp, "status_code", 0),
            "headers": dict(resp.headers),
            "body": resp_body[:8000],
            "body_length": len(resp_body),
            "success": resp.status_code < 400,
        }
    except requests.RequestException as e:
        resp_body = ""
        resp_obj = getattr(e, "response", None)
        status = 0
        headers = {}
        if resp_obj is not None:
            try:
                resp_body = resp_obj.text
                status = getattr(resp_obj, "status_code", 0)
                headers = dict(resp_obj.headers)
            except Exception:  # noqa: S110
                pass
        return {
            "status": status,
            "headers": headers,
            "body": (resp_body or "")[:8000],
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


def _build_url_with_tenant(url: str, tenant_param: str, tenant_value: str) -> str:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated = []
    found = False
    for key, value in query_pairs:
        if key.lower() == tenant_param.lower():
            updated.append((key, tenant_value))
            found = True
        else:
            updated.append((key, value))
    if not found:
        updated.append((tenant_param, tenant_value))
    return normalize_url(urlunparse(parsed._replace(query=urlencode(updated, doseq=True))))


def _build_request_with_tenant_header(
    headers: dict[str, str], tenant_header: str, tenant_value: str
) -> dict[str, str]:
    result = dict(headers)
    result[tenant_header] = tenant_value
    return result


def _compare_responses(
    original_body: str, swapped_body: str, original_data: Any, swapped_data: Any
) -> list[str]:
    signals: list[str] = []
    if original_body == swapped_body:
        return signals

    if isinstance(original_data, dict) and isinstance(swapped_data, dict):
        orig_keys = set(original_data.keys())
        swap_keys = set(swapped_data.keys())
        new_keys = swap_keys - orig_keys
        if new_keys:
            signals.append(f"tenant_keys_changed:{','.join(sorted(new_keys)[:5])}")
        removed_keys = orig_keys - swap_keys
        if removed_keys:
            signals.append(f"tenant_keys_removed:{','.join(sorted(removed_keys)[:5])}")

        for key in orig_keys & swap_keys:
            orig_val = original_data[key]
            swap_val = swapped_data[key]
            if orig_val != swap_val:
                if any(t in key.lower() for t in ("user", "email", "name", "data", "info")):
                    signals.append(f"tenant_field_changed:{key}")
                if isinstance(orig_val, (int, float)) and isinstance(swap_val, (int, float)):
                    if orig_val != swap_val:
                        signals.append(f"tenant_numeric_field_changed:{key}")

    if original_body and swapped_body:
        length_diff = abs(len(swapped_body) - len(original_body))
        if length_diff / max(len(original_body), 1) > 0.15:
            signals.append(f"tenant_body_length_diff:{length_diff}")

    return signals
