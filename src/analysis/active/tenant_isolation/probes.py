"""Main entry point for tenant isolation testing coordination."""

import logging
from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.analysis.helpers import classify_endpoint, endpoint_signature

from .constants import TENANT_PATH_PATTERN
from .detection import detect_tenant_parameters
from .findings import _build_finding
from .tests import test_cross_tenant_data_access, test_tenant_isolation, test_vertical_escalation

logger = logging.getLogger(__name__)


def run_tenant_isolation_probes(urls: list, responses: list, session=None, config=None) -> dict:
    """Run tenant isolation, vertical escalation, and cross-tenant access tests."""
    logger.info(
        "Running tenant isolation probes on %d URLs and %d responses", len(urls), len(responses)
    )

    config = config or {}
    max_urls = int(config.get("max_urls_to_test", 15))
    max_findings = int(config.get("max_findings", 10))
    test_types = config.get("test_types", ["isolation", "vertical", "cross_tenant"])

    detection = detect_tenant_parameters(urls, responses)
    multi_tenant = detection.get("multi_tenant_detected", False)
    tenant_params_list = detection.get("tenant_params", [])

    if not tenant_params_list and not multi_tenant:
        return {
            "multi_tenant_detected": False,
            "tenant_parameters": [],
            "findings": [],
            "summary": {
                "urls_tested": 0,
                "tests_performed": 0,
                "findings_count": 0,
                "note": "No tenant parameters or multi-tenant indicators detected",
            },
        }

    findings: list[dict[str, Any]] = []
    urls_to_test: list[str] = []

    for url_entry in urls[: max_urls * 2]:
        url = str(
            url_entry.get("url", url_entry) if isinstance(url_entry, dict) else url_entry
        ).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue
        if classify_endpoint(url) == "STATIC":
            continue
        urls_to_test.append(url)
        if len(urls_to_test) >= max_urls:
            break

    seen_endpoints: set[str] = set()
    total_tests = 0

    for url in urls_to_test:
        if len(findings) >= max_findings:
            break

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        query_param_names_lower = {k.lower() for k, _ in query_pairs}

        has_tenant_param = bool(query_param_names_lower & set(tenant_params_list))
        has_tenant_path = bool(TENANT_PATH_PATTERN.search(parsed.path))

        if not has_tenant_param and not has_tenant_path and not multi_tenant:
            continue

        tenant_param_info = None
        for key, value in query_pairs:
            if key.lower() in set(tenant_params_list):
                tenant_param_info = {
                    "parameter": key,
                    "value": value,
                    "location": "query",
                }
                break

        if not tenant_param_info and has_tenant_path:
            path_match = TENANT_PATH_PATTERN.search(parsed.path)
            if path_match:
                tenant_param_info = {
                    "parameter": "path_tenant",
                    "value": path_match.group(1),
                    "location": "path",
                }

        if not tenant_param_info and multi_tenant:
            tenant_param_info = {
                "parameter": "tenant_id",
                "value": "detected_multi_tenant",
                "location": "inferred",
            }

        if not tenant_param_info:
            continue

        if "isolation" in test_types:
            iso_result = test_tenant_isolation(url, tenant_param_info, session)
            total_tests += iso_result.get("tests_performed", 0)
            if iso_result.get("vulnerable"):
                findings.append(
                    _build_finding(
                        url=url,
                        severity=iso_result["severity"],
                        title=f"Tenant isolation failure: data leakage detected via {tenant_param_info['parameter']}",
                        signals=iso_result["signals"],
                        evidence={
                            "test_type": "tenant_isolation",
                            "tenant_parameter": tenant_param_info["parameter"],
                            "tenant_location": tenant_param_info["location"],
                            "tests": iso_result["evidence"],
                            "tests_performed": iso_result["tests_performed"],
                        },
                        explanation=(
                            f"Endpoint '{url}' shows tenant data leakage when "
                            f"tenant parameter '{tenant_param_info['parameter']}' is swapped. "
                            f"Performed {iso_result['tests_performed']} tests. "
                            f"Signals: {', '.join(sorted(set(iso_result['signals'])))}."
                        ),
                        status_code=iso_result.get("original_status"),
                    )
                )

        if "vertical" in test_types and len(findings) < max_findings:
            vert_result = test_vertical_escalation(url, tenant_param_info, session)
            total_tests += vert_result.get("tests_performed", 0)
            if vert_result.get("vulnerable"):
                findings.append(
                    _build_finding(
                        url=url,
                        severity=vert_result["severity"],
                        title=f"Vertical privilege escalation: admin tenant access via {tenant_param_info['parameter']}",
                        signals=vert_result["signals"],
                        evidence={
                            "test_type": "vertical_escalation",
                            "tenant_parameter": tenant_param_info["parameter"],
                            "tenant_location": tenant_param_info["location"],
                            "tests": vert_result["evidence"],
                            "tests_performed": vert_result["tests_performed"],
                        },
                        explanation=(
                            f"Endpoint '{url}' allows vertical privilege escalation "
                            f"via tenant parameter '{tenant_param_info['parameter']}'. "
                            f"Performed {vert_result['tests_performed']} tests. "
                            f"Signals: {', '.join(sorted(set(vert_result['signals'])))}."
                        ),
                        status_code=vert_result.get("original_status"),
                    )
                )

        if "cross_tenant" in test_types and len(findings) < max_findings:
            cross_result = test_cross_tenant_data_access(url, tenant_param_info, session)
            total_tests += cross_result.get("tests_performed", 0)
            if cross_result.get("vulnerable"):
                findings.append(
                    _build_finding(
                        url=url,
                        severity=cross_result["severity"],
                        title=f"Cross-tenant data access: unauthorized access via {tenant_param_info['parameter']}",
                        signals=cross_result["signals"],
                        evidence={
                            "test_type": "cross_tenant_data_access",
                            "tenant_parameter": tenant_param_info["parameter"],
                            "tenant_location": tenant_param_info["location"],
                            "tests": cross_result["evidence"],
                            "tests_performed": cross_result["tests_performed"],
                        },
                        explanation=(
                            f"Endpoint '{url}' allows cross-tenant data access "
                            f"via tenant parameter '{tenant_param_info['parameter']}'. "
                            f"Performed {cross_result['tests_performed']} tests. "
                            f"Signals: {', '.join(sorted(set(cross_result['signals'])))}."
                        ),
                        status_code=cross_result.get("original_status"),
                    )
                )

    findings.sort(
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f["severity"], 5),
            -f["confidence"],
            f["url"],
        )
    )

    return {
        "multi_tenant_detected": multi_tenant,
        "tenant_parameters": tenant_params_list,
        "findings": findings[:max_findings],
        "summary": {
            "urls_tested": len(urls_to_test),
            "tests_performed": total_tests,
            "findings_count": len(findings),
            "detection_details": detection,
        },
    }
