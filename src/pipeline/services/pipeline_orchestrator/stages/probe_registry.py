"""Probe registry and loader for active scanning."""

from __future__ import annotations

import functools
from typing import Any
from urllib.parse import urlparse

from src.execution.active_manifest import DEFAULT_ACTIVE_MANIFEST_REGISTRY
from src.recon.common import normalize_url


def _is_absolute_http_url(value: str) -> bool:
    parsed = urlparse(str(value or "").strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _normalize_scan_targets(targets: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in targets:
        value = normalize_url(str(raw or "").strip())
        if not value or not _is_absolute_http_url(value) or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def _build_priority_items(targets: list[str]) -> list[dict[str, Any]]:
    return [{"url": target} for target in _normalize_scan_targets(targets)]


def _build_response_cache() -> Any:
    from src.analysis.passive.runtime import RequestScheduler, ResponseCache

    scheduler = RequestScheduler(rate_per_second=4.0, capacity=2.0, adaptive_mode=False)
    return ResponseCache(
        timeout_seconds=12,
        max_bytes=120_000,
        max_workers=6,
        scheduler=scheduler,
        persistent_cache_path=None,
        cache_ttl_hours=1,
    )


@functools.lru_cache(maxsize=1)
def _load_active_probe_functions() -> dict[str, Any]:
    from src.analysis.active.auth_bypass.analyzer import run_auth_bypass_probes
    from src.analysis.active.cloud_metadata import cloud_metadata_active_probe
    from src.analysis.active.coordinator import (
        cors_preflight_probe,
        csrf_active_probe,
        file_upload_active_probe,
        hpp_active_probe,
        idor_active_probe,
        oauth_flow_analyzer,
        options_method_probe,
        sqli_safe_probe,
        trace_method_probe,
        websocket_message_probe,
    )
    from src.analysis.active.graphql import graphql_active_probe
    from src.analysis.active.http_smuggling import http2_probe, http_smuggling_probe
    from src.analysis.active.injection.command_injection import command_injection_active_probe
    from src.analysis.active.injection.crlf.crlf_probe import crlf_injection_probe
    from src.analysis.active.injection.deserialization import deserialization_probe
    from src.analysis.active.injection.host_header import host_header_injection_probe
    from src.analysis.active.injection.jwt_manipulation import jwt_manipulation_probe
    from src.analysis.active.injection.ldap import ldap_injection_active_probe
    from src.analysis.active.injection.nosql import nosql_injection_probe
    from src.analysis.active.injection.open_redirect import open_redirect_active_probe
    from src.analysis.active.injection.path_traversal import path_traversal_active_probe
    from src.analysis.active.injection.proxy_ssrf import proxy_ssrf_probe
    from src.analysis.active.injection.ssrf import ssrf_active_probe
    from src.analysis.active.injection.ssti import ssti_active_probe
    from src.analysis.active.injection.xpath import xpath_injection_active_probe
    from src.analysis.active.injection.xss_reflect_probe import xss_reflect_probe
    from src.analysis.active.injection.xxe import xxe_active_probe
    from src.analysis.active.jwt_attacks import run_jwt_attack_suite
    from src.analysis.active.jwt_attacks._helpers import JWT_RE
    from src.analysis.active.param_mining import param_mining_probe
    from src.analysis.intelligence.mutation_runtime import run_mutation_tests
    from src.analysis.json.active_probes import (
        filter_parameter_fuzzer,
        pagination_walker,
        parameter_dependency_tracker,
        state_transition_analyzer,
    )
    from src.analysis.response._core.response_analysis._diff_engine import response_diff_engine
    from src.fuzzing.payload_generator import generate_payload_suggestions
    from src.fuzzing.payload_generator_http import (
        generate_body_payloads,
        generate_header_payloads,
    )
    from src.pipeline.services.pipeline_orchestrator.stages.probe_runners import (
        _run_fuzzing_campaign_probe,
    )

    probes = {
        "run_auth_bypass_probes": run_auth_bypass_probes,
        "cloud_metadata_active_probe": cloud_metadata_active_probe,
        "cors_preflight_probe": cors_preflight_probe,
        "csrf_active_probe": csrf_active_probe,
        "command_injection_active_probe": command_injection_active_probe,
        "crlf_injection_probe": crlf_injection_probe,
        "deserialization_probe": deserialization_probe,
        "file_upload_active_probe": file_upload_active_probe,
        "filter_parameter_fuzzer": filter_parameter_fuzzer,
        "graphql_active_probe": graphql_active_probe,
        "host_header_injection_probe": host_header_injection_probe,
        "http2_probe": http2_probe,
        "http_smuggling_probe": http_smuggling_probe,
        "hpp_active_probe": hpp_active_probe,
        "idor_active_probe": idor_active_probe,
        "oauth_flow_analyzer": oauth_flow_analyzer,
        "ldap_injection_active_probe": ldap_injection_active_probe,
        "nosql_injection_probe": nosql_injection_probe,
        "open_redirect_active_probe": open_redirect_active_probe,
        "options_method_probe": options_method_probe,
        "pagination_walker": pagination_walker,
        "parameter_dependency_tracker": parameter_dependency_tracker,
        "path_traversal_active_probe": path_traversal_active_probe,
        "proxy_ssrf_probe": proxy_ssrf_probe,
        "generate_payload_suggestions": generate_payload_suggestions,
        "generate_header_payloads": generate_header_payloads,
        "generate_body_payloads": generate_body_payloads,
        "run_fuzzing_campaign_probe": _run_fuzzing_campaign_probe,
        "response_diff_engine": response_diff_engine,
        "run_jwt_attack_suite": run_jwt_attack_suite,
        "jwt_token_regex": JWT_RE,
        "sqli_safe_probe": sqli_safe_probe,
        "ssrf_active_probe": ssrf_active_probe,
        "ssti_active_probe": ssti_active_probe,
        "state_transition_analyzer": state_transition_analyzer,
        "trace_method_probe": trace_method_probe,
        "xss_reflect_probe": xss_reflect_probe,
        "xxe_active_probe": xxe_active_probe,
        "xpath_injection_active_probe": xpath_injection_active_probe,
        "websocket_message_probe": websocket_message_probe,
        "jwt_manipulation_probe": jwt_manipulation_probe,
        "run_mutation_tests": run_mutation_tests,
        "hidden_parameter_miner": param_mining_probe,
    }
    probes["_active_check_manifests"] = DEFAULT_ACTIVE_MANIFEST_REGISTRY.all()
    return probes
