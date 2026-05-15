"""Configuration management for the dashboard application.

Handles loading config templates, applying mode presets, managing module
selections, and ensuring analysis defaults are populated.
"""

import json
from typing import Any

from src.analysis.passive.catalog import PASSIVE_CHECK_NAMES
from src.dashboard.registry import MODE_PRESETS, MODULE_OPTIONS
from src.dashboard.runtime_controls import (
    apply_runtime_overrides as _apply_runtime_overrides,
)
from src.dashboard.runtime_controls import (
    build_form_defaults as _build_form_defaults,
)


def load_template(config_template: Any, output_root: Any) -> dict[str, Any]:
    """Load a configuration template from file or return defaults.

    Args:
        config_template: Path object pointing to the config JSON file.
        output_root: Root directory for pipeline output.

    Returns:
        Configuration dictionary with analysis defaults ensured.
    """
    if config_template.exists():
        loaded = json.loads(config_template.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("Config template must contain a JSON object.")
        return _ensure_analysis_defaults(loaded, output_root)
    return _ensure_analysis_defaults(
        {
            "target_name": "target",
            "output_dir": str(output_root),
            "http_timeout_seconds": 12,
            "mode": "idor",
            "cache": {"enabled": True},
            "tools": {
                "timeout_seconds": 120,
                "retry_attempts": 2,
                "retry_backoff_seconds": 1.0,
                "retry_backoff_multiplier": 2.0,
                "retry_max_backoff_seconds": 8.0,
                "retry_on_timeout": True,
                "retry_on_error": True,
                "subfinder": True,
                "assetfinder": True,
                "amass": False,
                "httpx": True,
                "gau": True,
                "waybackurls": True,
                "katana": True,
                "nuclei": True,
            },
            "httpx": {
                "threads": 80,
                "batch_size": 400,
                "batch_concurrency": 2,
                "fallback_threads": 48,
                "probe_timeout_seconds": 8,
                "extra_args": [],
            },
            "gau": {"timeout_seconds": 120, "extra_args": ["--providers", "wayback"]},
            "waybackurls": {"timeout_seconds": 120, "extra_args": []},
            "katana": {"extra_args": ["-silent"], "timeout_seconds": 30},
            "nuclei": {
                "severity": ["medium", "high", "critical"],
                "adaptive_tags": {},
                "fallback_tags": ["exposure", "misconfig", "default"],
                "extra_args": ["-rate-limit", "50"],
            },
            "analysis": {
                "enabled": True,
                "sensitive_data_scanner": True,
                "header_checker": True,
                "cookie_security_checker": True,
                "cors_misconfig_checker": True,
                "cache_control_checker": True,
                "jsonp_endpoint_checker": True,
                "frontend_config_exposure_checker": True,
                "directory_listing_checker": True,
                "debug_artifact_checker": True,
                "stored_xss_signal_detector": True,
                "token_leak_detector": True,
                "ssrf_candidate_finder": True,
                "idor_candidate_finder": True,
                "technology_fingerprint": True,
                "anomaly_detector": True,
                "response_snapshot_system": True,
                "response_diff_engine": True,
                "flow_detector": True,
                "smart_payload_suggestions": True,
                "cross_user_access_simulation": True,
                "role_based_endpoint_comparison": True,
                "privilege_escalation_detector": True,
                "access_boundary_tracker": True,
                "session_reuse_detection": True,
                "logout_invalidation_check": True,
                "multi_endpoint_auth_consistency_check": True,
                "token_scope_analyzer": True,
                "referer_propagation_tracking": True,
                "sensitive_field_detector": True,
                "nested_object_traversal": True,
                "endpoint_resource_groups": True,
                "bulk_endpoint_detector": True,
                "pagination_walker": True,
                "filter_parameter_fuzzer": True,
                "error_based_inference": True,
                "state_transition_analyzer": True,
                "parameter_dependency_tracker": True,
                "flow_integrity_checker": True,
                "race_condition_signal_analyzer": True,
                "version_diffing": True,
                "role_context_diff": True,
                "unauth_access_check": True,
                "rate_limit_signal_analyzer": True,
                "response_size_anomaly_detector": True,
                "payment_flow_intelligence": True,
                "payment_provider_detection": True,
                "behavior_analysis_layer": True,
                "redirect_chain_analyzer": True,
                "auth_boundary_redirect_detection": True,
                "options_method_probe": True,
                "origin_reflection_probe": True,
                "head_method_probe": True,
                "cors_preflight_probe": True,
                "trace_method_probe": False,
                "reflected_xss_probe": True,
                "request_rate_per_second": 2.5,
                "request_burst": 1.5,
                "auto_max_speed_mode": False,
                "deep_analysis_top_n": 9,
                "response_diff_limit": 10,
                "idor_compare_limit": 8,
                "behavior_analysis_limit": 6,
                "privilege_escalation_limit": 10,
                "state_transition_limit": 10,
                "parameter_dependency_limit": 10,
                "redirect_chain_limit": 8,
                "auth_boundary_redirect_limit": 8,
            },
            "scoring": {"weights": {"param": 5}, "modes": {}},
            "filters": {
                "priority_limit": {"default": 50},
                "max_collected_urls": 1400,
                "priority_keywords": [],
                "ignore_extensions": [],
            },
            "screenshots": {
                "enabled": False,
                "browser_paths": [],
                "max_hosts": 12,
                "per_url_timeout_seconds": 20,
            },
            "concurrency": {"nuclei_workers": 3},
            "output": {"dedupe_aliases": True, "write_artifact_manifest": True},
            "review": {
                "manual_verification_limit": 5,
                "top_findings_limit": 4,
                "verified_exploit_limit": 3,
            },
            "extensions": {"callback": {}},
            "notifications": {
                "webhook_url": "",
                "webhook_type": "generic",
                "notify_on_success": True,
                "notify_on_failure": True,
                "include_finding_summary": True,
            },
        },
        output_root,
    )


def default_module_names(config: dict[str, Any]) -> list[str]:
    selected = []
    for option in MODULE_OPTIONS:
        if option["kind"] == "tool" and config.get("tools", {}).get(option["name"]):
            selected.append(option["name"])
        elif option["kind"] == "screenshots" and config.get("screenshots", {}).get("enabled"):
            selected.append(option["name"])
        elif option["kind"] == "cache" and config.get("cache", {}).get("enabled"):
            selected.append(option["name"])
    return selected


def default_mode_name(config: dict[str, Any]) -> str:
    return str(config.get("mode", "idor")).strip().lower() or "idor"


def preset_module_names(config: dict[str, Any], mode_name: str) -> list[str]:
    preset = next((item for item in MODE_PRESETS if item["name"] == mode_name), None)
    if not preset:
        return default_module_names(config)
    return list(preset["modules"])


def apply_module_selection(config: dict[str, Any], selected_modules: set[str]) -> None:
    tools = config.setdefault("tools", {})
    for option in MODULE_OPTIONS:
        name = option["name"]
        if option["kind"] == "tool":
            tools[name] = name in selected_modules
        elif option["kind"] == "screenshots":
            config.setdefault("screenshots", {})["enabled"] = name in selected_modules
        elif option["kind"] == "cache":
            config.setdefault("cache", {})["enabled"] = name in selected_modules


def apply_mode_selection(config: dict[str, Any], mode_name: str) -> None:
    selected = (mode_name or default_mode_name(config)).strip().lower()
    config["mode"] = selected
    analysis = config.setdefault("analysis", {})
    filters = config.setdefault("filters", {})
    review = config.setdefault("review", {})
    httpx = config.setdefault("httpx", {})
    if selected == "safe":
        analysis["request_rate_per_second"] = min(
            float(analysis.get("request_rate_per_second", 2.5)), 2.5
        )
        analysis["request_burst"] = min(float(analysis.get("request_burst", 1.5)), 1.5)
        analysis["deep_analysis_top_n"] = min(int(analysis.get("deep_analysis_top_n", 9)), 9)
        analysis["response_diff_limit"] = min(int(analysis.get("response_diff_limit", 10)), 10)
        analysis["idor_compare_limit"] = min(int(analysis.get("idor_compare_limit", 8)), 8)
        analysis["behavior_analysis_limit"] = min(
            int(analysis.get("behavior_analysis_limit", 6)), 6
        )
        analysis["privilege_escalation_limit"] = min(
            int(analysis.get("privilege_escalation_limit", 10)), 10
        )
        analysis["state_transition_limit"] = min(
            int(analysis.get("state_transition_limit", 10)), 10
        )
        analysis["parameter_dependency_limit"] = min(
            int(analysis.get("parameter_dependency_limit", 10)), 10
        )
        analysis["redirect_chain_limit"] = min(int(analysis.get("redirect_chain_limit", 8)), 8)
        analysis["auth_boundary_redirect_limit"] = min(
            int(analysis.get("auth_boundary_redirect_limit", 8)), 8
        )
        analysis["trace_method_probe"] = False
        filters["priority_limit"] = 50
        filters["max_collected_urls"] = min(int(filters.get("max_collected_urls", 1400)), 1400)
        review["manual_verification_limit"] = min(
            int(review.get("manual_verification_limit", 5)), 5
        )
        review["top_findings_limit"] = min(int(review.get("top_findings_limit", 4)), 4)
        review["verified_exploit_limit"] = min(int(review.get("verified_exploit_limit", 3)), 3)
        httpx["threads"] = min(int(httpx.get("threads", 80)), 15)
        httpx["batch_concurrency"] = 1
        httpx["fallback_threads"] = min(int(httpx.get("fallback_threads", 48)), 24)
    elif selected == "aggressive":
        analysis["request_rate_per_second"] = max(
            float(analysis.get("request_rate_per_second", 6)), 10.0
        )
        analysis["request_burst"] = max(float(analysis.get("request_burst", 3)), 5.0)
        analysis["deep_analysis_top_n"] = max(int(analysis.get("deep_analysis_top_n", 15)), 20)
        filters["max_collected_urls"] = max(int(filters.get("max_collected_urls", 5000)), 8000)
        httpx["threads"] = max(int(httpx.get("threads", 80)), 100)
        httpx["batch_concurrency"] = max(int(httpx.get("batch_concurrency", 2)), 2)
        httpx["fallback_threads"] = max(int(httpx.get("fallback_threads", 48)), 64)


def build_form_defaults(config: dict[str, Any]) -> dict[str, str]:
    return _build_form_defaults(config)


def apply_runtime_overrides(config: dict[str, Any], overrides: dict[str, str]) -> None:
    _apply_runtime_overrides(config, overrides)


def _ensure_analysis_defaults(config: dict[str, Any], output_root: Any) -> dict[str, Any]:
    config.setdefault("output_dir", str(output_root))
    tools = config.setdefault("tools", {})
    tools.setdefault("timeout_seconds", 120)
    tools.setdefault("retry_attempts", 2)
    tools.setdefault("retry_backoff_seconds", 1.0)
    tools.setdefault("retry_backoff_multiplier", 2.0)
    tools.setdefault("retry_max_backoff_seconds", 8.0)
    tools.setdefault("retry_on_timeout", True)
    tools.setdefault("retry_on_error", True)
    config.setdefault("concurrency", {}).setdefault("nuclei_workers", 3)
    output = config.setdefault("output", {})
    output.setdefault("dedupe_aliases", True)
    output.setdefault("write_artifact_manifest", True)
    httpx = config.setdefault("httpx", {})
    httpx.setdefault("threads", 80)
    httpx.setdefault("batch_size", 400)
    httpx.setdefault("batch_concurrency", 2)
    httpx.setdefault("fallback_threads", 48)
    httpx.setdefault("probe_timeout_seconds", max(3, int(config.get("http_timeout_seconds", 12))))
    analysis = config.setdefault("analysis", {})
    for check_name in PASSIVE_CHECK_NAMES:
        if check_name == "trace_method_probe":
            analysis.setdefault(check_name, False)
        else:
            analysis.setdefault(check_name, True)
    analysis.setdefault("request_rate_per_second", 2.5)
    analysis.setdefault("request_burst", 1.5)
    analysis.setdefault("auto_max_speed_mode", False)
    analysis.setdefault("deep_analysis_top_n", 9)
    analysis.setdefault("response_diff_limit", 10)
    analysis.setdefault("parameter_pollution_limit", 16)
    analysis.setdefault("auth_header_variation_limit", 16)
    analysis.setdefault("json_mutation_limit", 16)
    analysis.setdefault("idor_compare_limit", 8)
    analysis.setdefault("payload_suggestion_limit", 18)
    analysis.setdefault("behavior_analysis_limit", 6)
    analysis.setdefault("privilege_escalation_limit", 10)
    analysis.setdefault("pagination_walk_limit", 24)
    analysis.setdefault("filter_fuzzer_limit", 24)
    analysis.setdefault("error_inference_limit", 24)
    analysis.setdefault("logout_invalidation_limit", 16)
    analysis.setdefault("state_transition_limit", 10)
    analysis.setdefault("parameter_dependency_limit", 10)
    analysis.setdefault("flow_break_limit", 12)
    analysis.setdefault("version_diff_limit", 20)
    analysis.setdefault("unauth_access_limit", 24)
    analysis.setdefault("redirect_chain_limit", 8)
    analysis.setdefault("auth_boundary_redirect_limit", 8)
    analysis.setdefault("options_probe_limit", 10)
    analysis.setdefault("origin_reflection_probe_limit", 8)
    analysis.setdefault("head_method_probe_limit", 8)
    analysis.setdefault("cors_preflight_probe_limit", 8)
    analysis.setdefault("trace_method_probe_limit", 5)
    analysis.setdefault("reflected_xss_probe_limit", 6)
    review = config.setdefault("review", {})
    review.setdefault("attack_graph_node_limit", 220)
    review.setdefault("attack_graph_edge_limit", 320)
    review.setdefault("attack_graph_chain_limit", 14)
    review.setdefault("attack_graph_max_depth", 4)
    extensions = config.setdefault("extensions", {})
    blackbox_validation = extensions.setdefault("blackbox_validation", {})
    selector = blackbox_validation.setdefault("selector", {})
    selector.setdefault("planner_enabled", True)
    selector.setdefault("max_plans", 8)
    notifications = config.setdefault("notifications", {})
    notifications.setdefault("webhook_url", "")
    notifications.setdefault("webhook_type", "generic")
    notifications.setdefault("notify_on_success", True)
    notifications.setdefault("notify_on_failure", True)
    notifications.setdefault("include_finding_summary", True)
    return config
