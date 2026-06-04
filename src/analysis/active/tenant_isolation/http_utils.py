"""HTTP utilities for tenant isolation testing."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.recon.common import normalize_url


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
