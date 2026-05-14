"""Endpoint intelligence signal collection.

Processes analysis results from all modules and populates
endpoint records with signals, evidence modules, and attack hints.
"""

from typing import Any

from src.analysis.helpers import meaningful_query_pairs

from ._registry import CONFIRMATION_MODULES, MODULE_SIGNAL_MAP, REPRODUCIBLE_MODULES


def _append_unique(items: list[str], value: str) -> None:
    cleaned = value.strip()
    if cleaned and cleaned not in items:
        items.append(cleaned)


def collect_module_signals(
    endpoint_map: dict[str, dict[str, Any]],
    analysis_results: dict[str, list[dict[str, Any]]],
    validation_summary: dict[str, Any] | None = None,
) -> None:
    """Collect signals from all analysis modules and populate endpoint records."""
    validation_results = (
        validation_summary.get("results", {}) if isinstance(validation_summary, dict) else {}
    )

    # Process standard module signals
    for module_name, signal_name in MODULE_SIGNAL_MAP.items():
        for item in analysis_results.get(module_name, []):
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            record = _ensure_endpoint(endpoint_map, url)
            record["signals"].add(signal_name)
            record["evidence_modules"].add(module_name)
            record["query_parameters"].update(key for key, _ in meaningful_query_pairs(url))
            if module_name in REPRODUCIBLE_MODULES:
                record["signals"].add("reproducible")
            if item.get("auth_bypass_variant") or item.get("step_skip_possible"):
                record["signals"].add("confirmed")
            if item.get("hint_message"):
                _append_unique(record["attack_hints"], str(item.get("hint_message")))

    # Process validation results
    for item in validation_results.get("open_redirect_validation", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        record = _ensure_endpoint(endpoint_map, url)
        record["signals"].update(
            {"redirect", "auth"} if item.get("auth_flow_endpoint") else {"redirect"}
        )
        record["evidence_modules"].add("open_redirect_validation")
        _append_unique(record["attack_hints"], str(item.get("hint_message", "")))

    for item in validation_results.get("ssrf_validation", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        record = _ensure_endpoint(endpoint_map, url)
        record["signals"].add("ssrf")
        record["evidence_modules"].add("ssrf_validation")
        _append_unique(record["attack_hints"], str(item.get("hint_message", "")))

    # Process response snapshots
    for item in analysis_results.get("response_snapshot_system", []):
        url = str(item.get("url", "")).strip()
        if url:
            _ensure_endpoint(endpoint_map, url)["response_snapshot"] = item

    # Process JSON analysis
    for item in analysis_results.get("json_response_parser", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        record = _ensure_endpoint(endpoint_map, url)
        record["signals"].add("json")
        if int(item.get("max_depth", 0)) >= 3:
            record["signals"].add("deep_json")
        record["parameter_sensitivity"] = max(
            record["parameter_sensitivity"], min(int(item.get("max_depth", 0)), 4)
        )

    for item in analysis_results.get("json_schema_inference", []):
        for url in item.get("example_urls", []):
            record = _ensure_endpoint(endpoint_map, str(url))
            markers = []
            if item.get("id_like"):
                markers.append(f"id_field:{item.get('field_name')}")
            if item.get("role_like"):
                markers.append(f"role_field:{item.get('field_name')}")
            if item.get("sensitive_like"):
                markers.append(f"sensitive_field:{item.get('field_name')}")
            for marker in markers:
                _append_unique(record["schema_markers"], marker)
            if markers:
                record["signals"].add("schema")

    # Process response diffs
    for item in analysis_results.get("response_diff_engine", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        record = _ensure_endpoint(endpoint_map, url)
        record["response_diff"] = item
        if item.get("changed"):
            record["signals"].add("response_diff")
        if item.get("status_changed"):
            record["signals"].add("status_change")
        if item.get("redirect_changed"):
            record["signals"].add("redirect_change")
        if item.get("content_changed"):
            record["signals"].add("content_change")
        if item.get("result_stable"):
            record["signals"].add("stable_diff")

    # Process payload suggestions
    for item in analysis_results.get("smart_payload_suggestions", []):
        url = str(item.get("url", "")).strip()
        if url:
            record = _ensure_endpoint(endpoint_map, url)
            suggestions = item.get("suggestions", [])
            record["payload_suggestions"] = suggestions
            from src.analysis.endpoint_intelligence_scoring import _parameter_sensitivity_score

            record["parameter_sensitivity"] = max(
                record["parameter_sensitivity"], _parameter_sensitivity_score(suggestions)
            )
            record["query_parameters"].update(
                str(entry.get("parameter", "")).strip().lower()
                for entry in suggestions
                if str(entry.get("parameter", "")).strip()
            )

    # Process resource groups
    for item in analysis_results.get("endpoint_resource_groups", []):
        resource = str(item.get("resource", "")).strip()
        for url in item.get("endpoints", []):
            if not url:
                continue
            record = _ensure_endpoint(endpoint_map, str(url))
            if resource:
                record["resource_group"] = resource

    # Process diff-based signals
    for module_name in CONFIRMATION_MODULES:
        for item in analysis_results.get(module_name, []):
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            record = _ensure_endpoint(endpoint_map, url)
            if (
                item.get("body_similarity") is not None
                and float(item.get("body_similarity", 1.0)) < 0.95
            ):
                record["signals"].add("content_change")
            if item.get("mutated_status") and item.get("original_status") != item.get(
                "mutated_status"
            ):
                record["signals"].add("status_change")

    # Process nested object traversal
    for item in analysis_results.get("nested_object_traversal", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        record = _ensure_endpoint(endpoint_map, url)
        record["flow_score"] = max(
            record["flow_score"], min(int(item.get("traversal_score", 0)) // 3, 8)
        )

    # Process response size anomaly
    for item in analysis_results.get("response_size_anomaly_detector", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        record = _ensure_endpoint(endpoint_map, url)
        record["resource_group"] = (
            str(item.get("resource_group", "")).strip() or record["resource_group"]
        )

    # Process payment intelligence
    for item in analysis_results.get("payment_flow_intelligence", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        record = _ensure_endpoint(endpoint_map, url)
        stage = str(item.get("payment_stage", "")).strip()
        if stage:
            record["signals"].add(f"payment_{stage}")
        if item.get("providers"):
            for provider in item.get("providers", [])[:3]:
                _append_unique(record["schema_markers"], f"payment_provider:{provider}")
        if item.get("payment_parameters"):
            record["parameter_sensitivity"] = max(
                record["parameter_sensitivity"], min(len(item.get("payment_parameters", [])) + 1, 6)
            )
        if item.get("hint_message"):
            _append_unique(record["attack_hints"], str(item.get("hint_message")))

    # Process flow detection
    for item in analysis_results.get("flow_detector", []):
        for url in item.get("chain", []):
            record = _ensure_endpoint(endpoint_map, str(url))
            record["signals"].update({"flow", "auth"})
            record["flow_labels"].add(str(item.get("label", "auth_flow")))
            record["auth_contexts"].add("auth_flow")
            _append_unique(
                record["attack_hints"],
                f"Check redirect chain consistency across the detected {item.get('label', 'auth flow')} chain.",
            )

    # Process behavior analysis
    for item in analysis_results.get("behavior_analysis_layer", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        record = _ensure_endpoint(endpoint_map, url)
        record["signals"].update({"behavior", *item.get("multi_signal_overlap", [])})
        record["query_parameters"].update(
            value
            for value in (
                str(item.get("parameter", "")).strip().lower(),
                str((item.get("request_context", {}) or {}).get("parameter", "")).strip().lower(),
            )
            if value
        )
        if item.get("trust_boundary_shift"):
            record["signals"].add("trust_boundary_shift")
            record["trust_boundary"] = "cross-host"
        if item.get("confirmed"):
            record["signals"].add("confirmed")
        if item.get("reproducible"):
            record["signals"].add("reproducible")
        if item.get("intra_run_confirmed"):
            record["signals"].add("intra_run_confirmed")
        if item.get("cross_run_reproducible"):
            record["signals"].add("cross_run_reproducible")
        if item.get("flow_transition", {}).get("changed"):
            record["signals"].add("flow_transition")
            record["flow_score"] = max(record["flow_score"], 6)
        record["evidence_modules"].add("behavior_analysis_layer")
        variant = str(item.get("variant", "")).strip()
        parameter = str(item.get("parameter", "")).strip()
        if parameter and variant:
            _append_unique(
                record["attack_hints"],
                f"Replay {parameter}={variant} and compare the stored before/after flow transition.",
            )

    # Process auth contexts
    for item in analysis_results.get("access_boundary_tracker", []):
        contexts = {
            _boundary_to_auth_context(state) for state in item.get("boundary_transitions", [])
        }
        for sample_url in item.get("sample_urls", []):
            if not sample_url:
                continue
            _ensure_endpoint(endpoint_map, str(sample_url))["auth_contexts"].update(contexts)

    for item in analysis_results.get("multi_endpoint_auth_consistency_check", []):
        for sample_url in item.get("accessible_examples", []):
            if sample_url:
                _ensure_endpoint(endpoint_map, str(sample_url))["auth_contexts"].add(
                    "authenticated"
                )
        for sample_url in item.get("restricted_examples", []):
            if sample_url:
                _ensure_endpoint(endpoint_map, str(sample_url))["auth_contexts"].add("restricted")

    for item in analysis_results.get("unauth_access_check", []):
        url = str(item.get("url", "")).strip()
        if url:
            _ensure_endpoint(endpoint_map, url)["auth_contexts"].update({"public", "authenticated"})

    for item in analysis_results.get("token_scope_analyzer", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        record = _ensure_endpoint(endpoint_map, url)
        if item.get("token_fields"):
            record["auth_contexts"].add("authenticated")
        if item.get("admin_scope_hint"):
            record["auth_contexts"].add("privileged")

    for item in analysis_results.get("role_based_endpoint_comparison", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        record = _ensure_endpoint(endpoint_map, url)
        record["auth_contexts"].add("authenticated")
        if "role" in item.get("role_contexts", []) or item.get("response_diff_strength") == "high":
            record["auth_contexts"].add("privileged")

    for item in analysis_results.get("privilege_escalation_detector", []):
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        record = _ensure_endpoint(endpoint_map, url)
        record["auth_contexts"].add("authenticated")
        if item.get("accessible_after_role_change"):
            record["auth_contexts"].add("privileged")


def _ensure_endpoint(endpoint_map: dict[str, dict[str, Any]], url: str) -> dict[str, Any]:
    """Get or create an endpoint record in the map."""
    from src.analysis.helpers import (
        endpoint_base_key,
        endpoint_signature,
        is_auth_flow_endpoint,
        meaningful_query_pairs,
    )

    key = endpoint_signature(url)
    existing = endpoint_map.get(key)
    if existing:
        return existing
    cached = {
        "endpoint_base_key": endpoint_base_key(url),
        "is_auth_flow": is_auth_flow_endpoint(url),
        "query_parameters": {key for key, _ in meaningful_query_pairs(url)},
    }
    record = {
        "url": url,
        "endpoint_key": key,
        "endpoint_base_key": cached["endpoint_base_key"],
        "endpoint_type": "AUTH" if cached["is_auth_flow"] else "GENERAL",
        "base_score": 0,
        "normalized_score": 0.0,
        "signals": set(),
        "evidence_modules": set(),
        "signal_cooccurrence": {},
        "flow_labels": set(),
        "attack_hints": [],
        "payload_suggestions": [],
        "response_diff": None,
        "response_snapshot": None,
        "parameter_sensitivity": 0,
        "trust_boundary": "same-host",
        "flow_score": 0,
        "evidence_confidence": 0.42,
        "resource_group": "",
        "schema_markers": [],
        "query_parameters": cached["query_parameters"],
        "auth_contexts": set(),
    }
    endpoint_map[key] = record
    return record


def _boundary_to_auth_context(state: str) -> str:
    lowered = str(state or "").strip().lower()
    if lowered == "private":
        return "authenticated"
    if lowered == "admin":
        return "privileged"
    return lowered
