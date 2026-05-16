"""Test functions for tenant isolation probing."""

import logging
from typing import Any

from .detection import _extract_json
from .http_utils import (
    _build_request_with_tenant_header,
    _build_url_with_tenant,
    _compare_responses,
    _safe_request,
)

logger = logging.getLogger(__name__)


def test_tenant_isolation(url: str, tenant_params: dict[str, Any], session: Any = None) -> dict[str, Any]:
    """Swap tenant IDs between requests and check for data leakage."""
    logger.info("Testing tenant isolation for %s with param %s", url, tenant_params)

    result: dict[str, Any] = {
        "vulnerable": False,
        "signals": [],
        "evidence": [],
        "severity": "info",
        "original_status": 0,
        "swapped_status": 0,
        "tests_performed": 0,
    }

    original_resp = _safe_request(url, timeout=8)
    if not original_resp or original_resp.get("status") in (404, 410, 503):
        return result

    original_status = original_resp.get("status", 0)
    original_body = str(original_resp.get("body") or original_resp.get("body_text") or "")
    original_headers = original_resp.get("headers", {})
    original_data = _extract_json(original_body)
    result["original_status"] = original_status

    tenant_param_name = tenant_params.get("parameter", "")
    original_tenant_value = tenant_params.get("value", "")
    location = tenant_params.get("location", "query")

    if not tenant_param_name or not original_tenant_value:
        return result

    fake_tenant_values = [
        "0",
        "1",
        "999999",
        "test_tenant",
        "other_org",
        "00000000-0000-0000-0000-000000000001",
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    ]

    for fake_value in fake_tenant_values:
        if fake_value.lower() == original_tenant_value.lower():
            continue

        result["tests_performed"] += 1

        if location == "query":
            test_url = _build_url_with_tenant(url, tenant_param_name, fake_value)
            test_headers = {
                "Cache-Control": "no-cache",
                "X-Tenant-Isolation-Probe": "1",
            }
            for k, v in original_headers.items():
                if k.lower() in ("authorization", "cookie", "x-csrf-token"):
                    test_headers[k] = v
            swapped_resp = _safe_request(test_url, headers=test_headers, timeout=10)

        elif location == "header":
            test_headers = {
                "Cache-Control": "no-cache",
                "X-Tenant-Isolation-Probe": "1",
            }
            for k, v in original_headers.items():
                if k.lower() in ("authorization", "cookie", "x-csrf-token"):
                    test_headers[k] = v
            test_headers = _build_request_with_tenant_header(
                test_headers, tenant_param_name, fake_value
            )
            swapped_resp = _safe_request(url, headers=test_headers, timeout=10)

        else:
            test_url = _build_url_with_tenant(url, tenant_param_name, fake_value)
            test_headers = {
                "Cache-Control": "no-cache",
                "X-Tenant-Isolation-Probe": "1",
            }
            for k, v in original_headers.items():
                if k.lower() in ("authorization", "cookie", "x-csrf-token"):
                    test_headers[k] = v
            swapped_resp = _safe_request(test_url, headers=test_headers, timeout=10)

        if not swapped_resp:
            continue

        swapped_status = swapped_resp.get("status", 0)
        swapped_body = str(swapped_resp.get("body") or swapped_resp.get("body_text") or "")
        swapped_data = _extract_json(swapped_body)
        result["swapped_status"] = swapped_status

        if swapped_status == 200 and original_status in (200, 201):
            signals = _compare_responses(original_body, swapped_body, original_data, swapped_data)
            if signals:
                result["signals"].extend(signals)
                result["evidence"].append(
                    {
                        "test_type": "tenant_swap",
                        "original_tenant": original_tenant_value,
                        "swapped_tenant": fake_value,
                        "original_status": original_status,
                        "swapped_status": swapped_status,
                        "signals": signals,
                    }
                )
                result["vulnerable"] = True
                break

        elif swapped_status == 200 and original_status in (401, 403):
            result["signals"].append("tenant_isolation_auth_bypass")
            result["evidence"].append(
                {
                    "test_type": "tenant_auth_bypass",
                    "original_tenant": original_tenant_value,
                    "swapped_tenant": fake_value,
                    "original_status": original_status,
                    "swapped_status": swapped_status,
                    "signals": ["tenant_isolation_auth_bypass"],
                }
            )
            result["vulnerable"] = True
            break

        elif swapped_status in (200, 201) and original_status in (200, 201):
            if original_data and swapped_data:
                if isinstance(original_data, dict) and isinstance(swapped_data, dict):
                    orig_ids = set()
                    swap_ids = set()
                    for key in original_data:
                        if "id" in key.lower() and isinstance(original_data[key], (str, int)):
                            orig_ids.add(str(original_data[key]))
                    for key in swapped_data:
                        if "id" in key.lower() and isinstance(swapped_data[key], (str, int)):
                            swap_ids.add(str(swapped_data[key]))
                    if orig_ids and swap_ids and orig_ids != swap_ids:
                        result["signals"].append("tenant_data_ids_differ")
                        result["evidence"].append(
                            {
                                "test_type": "tenant_data_comparison",
                                "original_tenant": original_tenant_value,
                                "swapped_tenant": fake_value,
                                "original_ids_sample": sorted(orig_ids)[:5],
                                "swapped_ids_sample": sorted(swap_ids)[:5],
                                "signals": ["tenant_data_ids_differ"],
                            }
                        )
                        result["vulnerable"] = True
                        break

    if result["vulnerable"]:
        if "tenant_isolation_auth_bypass" in result["signals"]:
            result["severity"] = "critical"
        elif any("field_changed" in s for s in result["signals"]):
            result["severity"] = "high"
        else:
            result["severity"] = "medium"

    return result


def test_vertical_escalation(url: str, tenant_params: dict[str, Any], session: Any = None) -> dict[str, Any]:
    """Test privilege escalation from user to admin tenant context."""
    logger.info("Testing vertical escalation for %s", url)

    result: dict[str, Any] = {
        "vulnerable": False,
        "signals": [],
        "evidence": [],
        "severity": "info",
        "original_status": 0,
        "escalated_status": 0,
        "tests_performed": 0,
    }

    original_resp = _safe_request(url, timeout=8)
    if not original_resp or original_resp.get("status") in (404, 410, 503):
        return result

    original_status = original_resp.get("status", 0)
    original_body = str(original_resp.get("body") or original_resp.get("body_text") or "")
    original_headers = original_resp.get("headers", {})
    result["original_status"] = original_status

    tenant_param_name = tenant_params.get("parameter", "")
    original_tenant_value = tenant_params.get("value", "")
    location = tenant_params.get("location", "query")

    if not tenant_param_name:
        return result

    admin_tenant_values = [
        "admin",
        "root",
        "superadmin",
        "master",
        "system",
        "1",
        "0",
        "platform",
        "global",
        "default",
    ]

    for admin_value in admin_tenant_values:
        if admin_value.lower() == original_tenant_value.lower():
            continue

        result["tests_performed"] += 1

        if location == "header":
            test_headers = dict(original_headers)
            test_headers[tenant_param_name] = admin_value
            test_headers["Cache-Control"] = "no-cache"
            test_headers["X-Tenant-Escalation-Probe"] = "1"
            escalated_resp = _safe_request(url, headers=test_headers, timeout=10)
        else:
            test_url = _build_url_with_tenant(url, tenant_param_name, admin_value)
            test_headers = {
                "Cache-Control": "no-cache",
                "X-Tenant-Escalation-Probe": "1",
            }
            for k, v in original_headers.items():
                if k.lower() in ("authorization", "cookie", "x-csrf-token"):
                    test_headers[k] = v
            escalated_resp = _safe_request(test_url, headers=test_headers, timeout=10)

        if not escalated_resp:
            continue

        escalated_status = escalated_resp.get("status", 0)
        escalated_body = str(escalated_resp.get("body") or escalated_resp.get("body_text") or "")
        result["escalated_status"] = escalated_status

        if escalated_status == 200 and original_status in (401, 403):
            result["signals"].append("vertical_escalation_auth_bypass")
            result["evidence"].append(
                {
                    "test_type": "vertical_escalation",
                    "original_tenant": original_tenant_value,
                    "admin_tenant": admin_value,
                    "original_status": original_status,
                    "escalated_status": escalated_status,
                    "signals": ["vertical_escalation_auth_bypass"],
                }
            )
            result["vulnerable"] = True
            break

        if escalated_status == 200 and original_status in (200, 201):
            escalated_data = _extract_json(escalated_body)
            original_data = _extract_json(original_body)
            if isinstance(original_data, dict) and isinstance(escalated_data, dict):
                admin_indicators = {"admin", "superuser", "root", "master", "system"}
                for key, value in escalated_data.items():
                    if isinstance(value, str) and any(a in value.lower() for a in admin_indicators):
                        if key.lower() in ("role", "type", "level", "access", "privilege", "scope"):
                            result["signals"].append(f"vertical_escalation_admin_response:{key}")
                            result["evidence"].append(
                                {
                                    "test_type": "vertical_escalation_admin_data",
                                    "admin_tenant": admin_value,
                                    "admin_field": key,
                                    "admin_value_preview": str(value)[:100],
                                    "signals": [f"vertical_escalation_admin_response:{key}"],
                                }
                            )
                            result["vulnerable"] = True
                            break
                if result["vulnerable"]:
                    break

                orig_keys = set(original_data.keys())
                esc_keys = set(escalated_data.keys())
                new_admin_keys = esc_keys - orig_keys
                if new_admin_keys and any(
                    "admin" in k.lower() or "role" in k.lower() for k in new_admin_keys
                ):
                    result["signals"].append("vertical_escalation_new_admin_fields")
                    result["evidence"].append(
                        {
                            "test_type": "vertical_escalation_new_fields",
                            "admin_tenant": admin_value,
                            "new_keys": sorted(new_admin_keys)[:10],
                            "signals": ["vertical_escalation_new_admin_fields"],
                        }
                    )
                    result["vulnerable"] = True
                    break

    if result["vulnerable"]:
        if "vertical_escalation_auth_bypass" in result["signals"]:
            result["severity"] = "critical"
        else:
            result["severity"] = "high"

    return result


def test_cross_tenant_data_access(url: str, tenant_params: dict[str, Any], session: Any = None) -> dict[str, Any]:
    """Test accessing another tenant's data by swapping tenant identifiers."""
    logger.info("Testing cross-tenant data access for %s", url)

    result: dict[str, Any] = {
        "vulnerable": False,
        "signals": [],
        "evidence": [],
        "severity": "info",
        "original_status": 0,
        "cross_tenant_status": 0,
        "tests_performed": 0,
    }

    original_resp = _safe_request(url, timeout=8)
    if not original_resp or original_resp.get("status") in (404, 410, 503):
        return result

    original_status = original_resp.get("status", 0)
    original_body = str(original_resp.get("body") or original_resp.get("body_text") or "")
    original_headers = original_resp.get("headers", {})
    original_data = _extract_json(original_body)
    result["original_status"] = original_status

    tenant_param_name = tenant_params.get("parameter", "")
    original_tenant_value = tenant_params.get("value", "")
    location = tenant_params.get("location", "query")

    if not tenant_param_name or not original_tenant_value:
        return result

    cross_tenant_values = [
        "cross_tenant_test",
        "external_org",
        "other_company",
        "different_workspace",
        "999999",
        "888888",
        "ffffffff-ffff-4fff-8fff-ffffffffffff",
    ]

    for cross_value in cross_tenant_values:
        if cross_value.lower() == original_tenant_value.lower():
            continue

        result["tests_performed"] += 1

        if location == "header":
            test_headers = dict(original_headers)
            test_headers[tenant_param_name] = cross_value
            test_headers["Cache-Control"] = "no-cache"
            test_headers["X-Cross-Tenant-Probe"] = "1"
            cross_resp = _safe_request(url, headers=test_headers, timeout=10)
        else:
            test_url = _build_url_with_tenant(url, tenant_param_name, cross_value)
            test_headers = {
                "Cache-Control": "no-cache",
                "X-Cross-Tenant-Probe": "1",
            }
            for k, v in original_headers.items():
                if k.lower() in ("authorization", "cookie", "x-csrf-token"):
                    test_headers[k] = v
            cross_resp = _safe_request(test_url, headers=test_headers, timeout=10)

        if not cross_resp:
            continue

        cross_status = cross_resp.get("status", 0)
        cross_body = str(cross_resp.get("body") or cross_resp.get("body_text") or "")
        cross_data = _extract_json(cross_body)
        result["cross_tenant_status"] = cross_status

        if cross_status == 200 and original_status in (200, 201):
            signals = _compare_responses(original_body, cross_body, original_data, cross_data)
            if signals:
                result["signals"].extend(signals)
                result["evidence"].append(
                    {
                        "test_type": "cross_tenant_access",
                        "original_tenant": original_tenant_value,
                        "cross_tenant": cross_value,
                        "original_status": original_status,
                        "cross_status": cross_status,
                        "signals": signals,
                    }
                )
                result["vulnerable"] = True
                break

        if cross_status == 200 and original_status in (401, 403):
            result["signals"].append("cross_tenant_unauthorized_access")
            result["evidence"].append(
                {
                    "test_type": "cross_tenant_unauthorized",
                    "original_tenant": original_tenant_value,
                    "cross_tenant": cross_value,
                    "original_status": original_status,
                    "cross_status": cross_status,
                    "signals": ["cross_tenant_unauthorized_access"],
                }
            )
            result["vulnerable"] = True
            break

    if result["vulnerable"]:
        if "cross_tenant_unauthorized_access" in result["signals"]:
            result["severity"] = "critical"
        elif any("field_changed" in s for s in result["signals"]):
            result["severity"] = "high"
        else:
            result["severity"] = "medium"

    return result
