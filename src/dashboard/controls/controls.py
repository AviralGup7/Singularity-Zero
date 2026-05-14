"""Runtime control definitions.

Defines NumericControlSpec and ToggleControlSpec dataclasses and
the full list of runtime controls for the dashboard.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NumericControlSpec:
    name: str
    label: str
    path: tuple[str, ...]
    fallback: int | float
    minimum: int | float = 1
    maximum: int | float | None = None
    step: int | float | None = None
    value_type: str = "int"
    default_resolver: Callable[[dict[str, Any]], str] | None = None

    def __post_init__(self) -> None:
        if self.value_type not in {"int", "float"}:
            raise ValueError(f"Invalid value_type for {self.name}: {self.value_type}")
        if (
            self.minimum is not None
            and self.value_type == "int"
            and int(self.minimum) != self.minimum
        ):
            raise ValueError(f"Invalid minimum for integer control {self.name}: {self.minimum}")
        if (
            self.maximum is not None
            and self.value_type == "int"
            and int(self.maximum) != self.maximum
        ):
            raise ValueError(f"Invalid maximum for integer control {self.name}: {self.maximum}")
        if self.step is not None and self.step <= 0:
            raise ValueError(f"Invalid step for {self.name}: {self.step}")
        if self.maximum is not None and self.minimum is not None and self.maximum < self.minimum:
            raise ValueError(
                f"Invalid range for {self.name}: maximum {self.maximum} < minimum {self.minimum}"
            )

    def default_value(self, config: dict[str, Any]) -> str:
        if self.default_resolver is not None:
            return self.default_resolver(config)
        from .widgets import _nested_get

        return str(_nested_get(config, self.path, self.fallback))


@dataclass(frozen=True)
class ToggleControlSpec:
    name: str
    title: str
    description: str
    fallback: bool
    config_path: tuple[str, ...] | None = None
    execution_option: bool = False

    def default_value(self, config: dict[str, Any]) -> str:
        if self.config_path is None:
            return "1" if self.fallback else "0"
        from .widgets import _nested_get

        return "1" if bool(_nested_get(config, self.config_path, self.fallback)) else "0"


RUNTIME_NUMERIC_CONTROLS: list[NumericControlSpec] = [
    NumericControlSpec(
        "priority_limit",
        "Priority Limit",
        ("filters", "priority_limit"),
        100,
        maximum=500,
        default_resolver=lambda config: str(
            config.get("filters", {}).get("priority_limit", 100)
            if not isinstance(config.get("filters", {}).get("priority_limit", 100), dict)
            else config.get("filters", {}).get("priority_limit", {}).get("default", 100)
        ),
    ),
    NumericControlSpec(
        "max_collected_urls",
        "Max Collected URLs",
        ("filters", "max_collected_urls"),
        5000,
        maximum=10000,
    ),
    NumericControlSpec(
        "tool_timeout_seconds", "Tool Timeout (s)", ("tools", "timeout_seconds"), 120, maximum=300
    ),
    NumericControlSpec(
        "nuclei_timeout_seconds",
        "Nuclei Timeout (s)",
        ("nuclei", "timeout_seconds"),
        120,
        maximum=120,
    ),
    NumericControlSpec("httpx_threads", "HTTPX Threads", ("httpx", "threads"), 80, maximum=200),
    NumericControlSpec(
        "httpx_batch_size", "HTTPX Batch Size", ("httpx", "batch_size"), 400, maximum=2000
    ),
    NumericControlSpec(
        "httpx_batch_concurrency",
        "HTTPX Batch Workers",
        ("httpx", "batch_concurrency"),
        2,
        maximum=10,
    ),
    NumericControlSpec(
        "httpx_fallback_threads",
        "Fallback Probe Threads",
        ("httpx", "fallback_threads"),
        48,
        maximum=256,
    ),
    NumericControlSpec(
        "httpx_probe_timeout_seconds",
        "HTTPX Probe Timeout (s)",
        ("httpx", "probe_timeout_seconds"),
        8,
        maximum=60,
    ),
    NumericControlSpec(
        "screenshot_max_hosts", "Screenshot Hosts", ("screenshots", "max_hosts"), 12, maximum=100
    ),
    NumericControlSpec(
        "analysis_timeout_seconds",
        "Analysis Timeout (s)",
        ("analysis", "timeout_seconds"),
        12,
        maximum=600,
        default_resolver=lambda config: str(
            config.get("analysis", {}).get(
                "timeout_seconds", config.get("http_timeout_seconds", 12)
            )
        ),
    ),
    NumericControlSpec(
        "request_rate_per_second",
        "Request Rate / sec",
        ("analysis", "request_rate_per_second"),
        6,
        minimum=0.1,
        maximum=100.0,
        step=0.1,
        value_type="float",
    ),
    NumericControlSpec(
        "request_burst",
        "Request Burst",
        ("analysis", "request_burst"),
        3,
        minimum=1.0,
        maximum=50.0,
        step=0.1,
        value_type="float",
    ),
    NumericControlSpec(
        "deep_analysis_top_n",
        "Deep Analysis Top N",
        ("analysis", "deep_analysis_top_n"),
        15,
        maximum=100,
    ),
    NumericControlSpec(
        "feedback_target_limit",
        "Feedback Target Limit",
        ("nuclei", "feedback_target_limit"),
        40,
        maximum=200,
    ),
    NumericControlSpec(
        "manual_verification_limit",
        "Manual Queue Size",
        ("review", "manual_verification_limit"),
        8,
        maximum=50,
    ),
    NumericControlSpec(
        "top_findings_limit", "Top Findings Count", ("review", "top_findings_limit"), 5, maximum=50
    ),
    NumericControlSpec(
        "verified_exploit_limit",
        "Verified Exploit Slots",
        ("review", "verified_exploit_limit"),
        5,
        maximum=50,
    ),
    NumericControlSpec(
        "response_diff_limit",
        "Response Diff Limit",
        ("analysis", "response_diff_limit"),
        16,
        maximum=100,
    ),
    NumericControlSpec(
        "parameter_pollution_limit",
        "Parameter Pollution Limit",
        ("analysis", "parameter_pollution_limit"),
        16,
        maximum=100,
    ),
    NumericControlSpec(
        "auth_header_variation_limit",
        "Auth Header Variation Limit",
        ("analysis", "auth_header_variation_limit"),
        16,
        maximum=100,
    ),
    NumericControlSpec(
        "json_mutation_limit",
        "JSON Mutation Limit",
        ("analysis", "json_mutation_limit"),
        16,
        maximum=100,
    ),
    NumericControlSpec(
        "idor_compare_limit",
        "IDOR Compare Limit",
        ("analysis", "idor_compare_limit"),
        12,
        maximum=100,
    ),
    NumericControlSpec(
        "payload_suggestion_limit",
        "Payload Suggestions",
        ("analysis", "payload_suggestion_limit"),
        18,
        maximum=100,
    ),
    NumericControlSpec(
        "behavior_analysis_limit",
        "Behavior Replay Limit",
        ("analysis", "behavior_analysis_limit"),
        12,
        maximum=100,
    ),
    NumericControlSpec(
        "privilege_escalation_limit",
        "Privilege Escalation Limit",
        ("analysis", "privilege_escalation_limit"),
        20,
        maximum=100,
    ),
    NumericControlSpec(
        "pagination_walk_limit",
        "Pagination Walk Limit",
        ("analysis", "pagination_walk_limit"),
        24,
        maximum=200,
    ),
    NumericControlSpec(
        "filter_fuzzer_limit",
        "Filter Fuzzer Limit",
        ("analysis", "filter_fuzzer_limit"),
        24,
        maximum=200,
    ),
    NumericControlSpec(
        "error_inference_limit",
        "Error Inference Limit",
        ("analysis", "error_inference_limit"),
        24,
        maximum=200,
    ),
    NumericControlSpec(
        "logout_invalidation_limit",
        "Logout Check Limit",
        ("analysis", "logout_invalidation_limit"),
        16,
        maximum=100,
    ),
    NumericControlSpec(
        "state_transition_limit",
        "State Transition Limit",
        ("analysis", "state_transition_limit"),
        20,
        maximum=100,
    ),
    NumericControlSpec(
        "parameter_dependency_limit",
        "Parameter Dependency Limit",
        ("analysis", "parameter_dependency_limit"),
        20,
        maximum=100,
    ),
    NumericControlSpec(
        "flow_break_limit", "Flow Break Limit", ("analysis", "flow_break_limit"), 12, maximum=100
    ),
    NumericControlSpec(
        "version_diff_limit",
        "Version Diff Limit",
        ("analysis", "version_diff_limit"),
        20,
        maximum=100,
    ),
    NumericControlSpec(
        "unauth_access_limit",
        "Unauth Access Limit",
        ("analysis", "unauth_access_limit"),
        24,
        maximum=200,
    ),
    NumericControlSpec(
        "redirect_chain_limit",
        "Redirect Chain Limit",
        ("analysis", "redirect_chain_limit"),
        20,
        maximum=100,
    ),
    NumericControlSpec(
        "auth_boundary_redirect_limit",
        "Auth Redirect Limit",
        ("analysis", "auth_boundary_redirect_limit"),
        20,
        maximum=100,
    ),
    NumericControlSpec(
        "options_probe_limit",
        "OPTIONS Probe Limit",
        ("analysis", "options_probe_limit"),
        10,
        maximum=50,
    ),
    NumericControlSpec(
        "origin_reflection_probe_limit",
        "Origin Probe Limit",
        ("analysis", "origin_reflection_probe_limit"),
        8,
        maximum=50,
    ),
    NumericControlSpec(
        "head_method_probe_limit",
        "HEAD Probe Limit",
        ("analysis", "head_method_probe_limit"),
        8,
        maximum=50,
    ),
    NumericControlSpec(
        "cors_preflight_probe_limit",
        "Preflight Probe Limit",
        ("analysis", "cors_preflight_probe_limit"),
        8,
        maximum=50,
    ),
    NumericControlSpec(
        "trace_method_probe_limit",
        "TRACE Probe Limit",
        ("analysis", "trace_method_probe_limit"),
        5,
        maximum=50,
    ),
    NumericControlSpec(
        "reflected_xss_probe_limit",
        "Reflected XSS Probe Limit",
        ("analysis", "reflected_xss_probe_limit"),
        6,
        maximum=50,
    ),
    NumericControlSpec(
        "attack_graph_node_limit",
        "Attack Graph Node Limit",
        ("review", "attack_graph_node_limit"),
        220,
        maximum=1000,
    ),
    NumericControlSpec(
        "attack_graph_edge_limit",
        "Attack Graph Edge Limit",
        ("review", "attack_graph_edge_limit"),
        320,
        maximum=2000,
    ),
    NumericControlSpec(
        "attack_graph_chain_limit",
        "Attack Graph Chain Limit",
        ("review", "attack_graph_chain_limit"),
        14,
        maximum=100,
    ),
    NumericControlSpec(
        "attack_graph_max_depth",
        "Attack Graph Max Depth",
        ("review", "attack_graph_max_depth"),
        4,
        maximum=10,
    ),
    NumericControlSpec(
        "validation_plan_limit",
        "Validation Plan Limit",
        ("extensions", "blackbox_validation", "selector", "max_plans"),
        8,
        maximum=50,
    ),
    NumericControlSpec(
        "path_traversal_limit",
        "Path Traversal Limit",
        ("analysis", "path_traversal_limit"),
        12,
        maximum=100,
    ),
    NumericControlSpec(
        "command_injection_limit",
        "Command Injection Limit",
        ("analysis", "command_injection_limit"),
        10,
        maximum=100,
    ),
    NumericControlSpec(
        "xxe_probe_limit", "XXE Probe Limit", ("analysis", "xxe_probe_limit"), 8, maximum=50
    ),
    NumericControlSpec(
        "ssrf_probe_limit", "SSRF Probe Limit", ("analysis", "ssrf_probe_limit"), 10, maximum=100
    ),
    NumericControlSpec(
        "open_redirect_limit",
        "Open Redirect Limit",
        ("analysis", "open_redirect_limit"),
        10,
        maximum=100,
    ),
    NumericControlSpec(
        "crlf_injection_limit",
        "CRLF Injection Limit",
        ("analysis", "crlf_injection_limit"),
        10,
        maximum=100,
    ),
    NumericControlSpec(
        "host_header_limit", "Host Header Limit", ("analysis", "host_header_limit"), 8, maximum=50
    ),
    NumericControlSpec(
        "ssti_probe_limit", "SSTI Probe Limit", ("analysis", "ssti_probe_limit"), 10, maximum=100
    ),
    NumericControlSpec(
        "nosql_injection_limit",
        "NoSQL Injection Limit",
        ("analysis", "nosql_injection_limit"),
        10,
        maximum=100,
    ),
    NumericControlSpec(
        "deserialization_limit",
        "Deserialization Limit",
        ("analysis", "deserialization_limit"),
        8,
        maximum=50,
    ),
    NumericControlSpec(
        "smuggling_probe_limit",
        "Smuggling Probe Limit",
        ("analysis", "smuggling_probe_limit"),
        10,
        maximum=100,
    ),
    NumericControlSpec(
        "http2_probe_limit", "HTTP/2 Probe Limit", ("analysis", "http2_probe_limit"), 8, maximum=50
    ),
    NumericControlSpec(
        "oauth_probe_limit", "OAuth Probe Limit", ("analysis", "oauth_probe_limit"), 10, maximum=100
    ),
    NumericControlSpec(
        "websocket_probe_limit",
        "WebSocket Probe Limit",
        ("analysis", "websocket_probe_limit"),
        8,
        maximum=50,
    ),
]

RUNTIME_TOGGLE_CONTROLS: list[ToggleControlSpec] = [
    ToggleControlSpec(
        "analysis_enabled",
        "Enable Passive Analysis",
        "Run heuristics, fingerprints, anomaly detection, and summary finding generation.",
        True,
        config_path=("analysis", "enabled"),
    ),
    ToggleControlSpec(
        "enable_idor_comparison",
        "Enable IDOR Comparison",
        "Allow lightweight id=1 versus id=2 response comparison for top candidates.",
        True,
        config_path=("analysis", "enable_idor_comparison"),
    ),
    ToggleControlSpec(
        "auto_max_speed_mode",
        "Auto Max-Speed Mode",
        "Let passive analysis ramp request rate up until latency or transient failures trigger a safe backoff and retry cycle.",
        False,
        config_path=("analysis", "auto_max_speed_mode"),
    ),
    ToggleControlSpec(
        "validation_planner_enabled",
        "Enable Validation Chain Planner",
        "Enable compound rule-based validation planning (required sessions, ordered steps, and stop conditions).",
        True,
        config_path=("extensions", "blackbox_validation", "selector", "planner_enabled"),
    ),
    ToggleControlSpec(
        "refresh_cache",
        "Refresh Recon Cache",
        "Ignore cached subdomains and URLs for this run and recollect them.",
        False,
        execution_option=True,
    ),
    ToggleControlSpec(
        "skip_crtsh",
        "Skip crt.sh",
        "Disable certificate-transparency scraping for this run when you want lower noise or faster startup.",
        False,
        execution_option=True,
    ),
    ToggleControlSpec(
        "dry_run",
        "Dry Run Only",
        "Validate scope and tool availability without starting a full recon run.",
        False,
        execution_option=True,
    ),
]

RUNTIME_FORM_FIELD_NAMES: set[str] = {spec.name for spec in RUNTIME_NUMERIC_CONTROLS} | {
    spec.name for spec in RUNTIME_TOGGLE_CONTROLS
}
EXECUTION_TOGGLE_CONTROLS: list[ToggleControlSpec] = [
    spec for spec in RUNTIME_TOGGLE_CONTROLS if spec.execution_option
]
CONFIG_TOGGLE_CONTROLS: list[ToggleControlSpec] = [
    spec for spec in RUNTIME_TOGGLE_CONTROLS if spec.config_path is not None
]
