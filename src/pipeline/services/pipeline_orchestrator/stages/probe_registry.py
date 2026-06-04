"""Probe registry and loader for active scanning."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from src.execution.active_manifest import DEFAULT_ACTIVE_MANIFEST_REGISTRY
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)


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


def _unavailable_probe(name: str, exc: BaseException) -> Any:
    """Return a placeholder probe that raises a clear ``NotImplementedError``.

    Used as a fault-isolation fallback: if a single probe module fails to
    import (e.g. optional dependency missing) the active-scan stage still
    runs with the rest of the probes and the failure is recorded in
    ``module_metrics`` rather than aborting the whole stage.
    """

    def _stub(*_args: Any, **_kwargs: Any) -> Any:
        raise NotImplementedError(
            f"Probe {name!r} is unavailable: {type(exc).__name__}: {exc}"
        )

    return _stub


def _try_import(name: str, module_path: str, attr: str) -> Any:
    try:
        module = __import__(module_path, fromlist=[attr])
        return getattr(module, attr)
    except (ImportError, AttributeError, ModuleNotFoundError) as exc:
        logger.warning("Probe %s unavailable: %s", name, exc)
        return _unavailable_probe(name, exc)


def _load_active_probe_functions() -> dict[str, Any]:
    """Build the active-probe function registry with per-probe fault isolation.

    The previous implementation used ``@functools.lru_cache(maxsize=1)``
    which (a) returned the same dict across calls so any in-place mutation
    would leak state, and (b) failed catastrophically if any one of the
    40+ imports raised. We now build a fresh dict on every call and
    isolate each import so a single missing module cannot abort the
    whole active-scan stage.
    """
    probes: dict[str, Any] = {
        "run_auth_bypass_probes": _try_import(
            "run_auth_bypass_probes",
            "src.analysis.active.auth_bypass.analyzer",
            "run_auth_bypass_probes",
        ),
        "cloud_metadata_active_probe": _try_import(
            "cloud_metadata_active_probe",
            "src.analysis.active.cloud_metadata",
            "cloud_metadata_active_probe",
        ),
        "cors_preflight_probe": _try_import(
            "cors_preflight_probe",
            "src.analysis.active.coordinator",
            "cors_preflight_probe",
        ),
        "csrf_active_probe": _try_import(
            "csrf_active_probe",
            "src.analysis.active.coordinator",
            "csrf_active_probe",
        ),
        "file_upload_active_probe": _try_import(
            "file_upload_active_probe",
            "src.analysis.active.coordinator",
            "file_upload_active_probe",
        ),
        "hpp_active_probe": _try_import(
            "hpp_active_probe",
            "src.analysis.active.coordinator",
            "hpp_active_probe",
        ),
        "idor_active_probe": _try_import(
            "idor_active_probe",
            "src.analysis.active.coordinator",
            "idor_active_probe",
        ),
        "oauth_flow_analyzer": _try_import(
            "oauth_flow_analyzer",
            "src.analysis.active.coordinator",
            "oauth_flow_analyzer",
        ),
        "options_method_probe": _try_import(
            "options_method_probe",
            "src.analysis.active.coordinator",
            "options_method_probe",
        ),
        "sqli_safe_probe": _try_import(
            "sqli_safe_probe",
            "src.analysis.active.coordinator",
            "sqli_safe_probe",
        ),
        "trace_method_probe": _try_import(
            "trace_method_probe",
            "src.analysis.active.coordinator",
            "trace_method_probe",
        ),
        "websocket_message_probe": _try_import(
            "websocket_message_probe",
            "src.analysis.active.coordinator",
            "websocket_message_probe",
        ),
        "graphql_active_probe": _try_import(
            "graphql_active_probe",
            "src.analysis.active.graphql",
            "graphql_active_probe",
        ),
        "http2_probe": _try_import(
            "http2_probe",
            "src.analysis.active.http_smuggling",
            "http2_probe",
        ),
        "http_smuggling_probe": _try_import(
            "http_smuggling_probe",
            "src.analysis.active.http_smuggling",
            "http_smuggling_probe",
        ),
        "command_injection_active_probe": _try_import(
            "command_injection_active_probe",
            "src.analysis.active.injection.command_injection",
            "command_injection_active_probe",
        ),
        "crlf_injection_probe": _try_import(
            "crlf_injection_probe",
            "src.analysis.active.injection.crlf.crlf_probe",
            "crlf_injection_probe",
        ),
        "deserialization_probe": _try_import(
            "deserialization_probe",
            "src.analysis.active.injection.deserialization",
            "deserialization_probe",
        ),
        "host_header_injection_probe": _try_import(
            "host_header_injection_probe",
            "src.analysis.active.injection.host_header",
            "host_header_injection_probe",
        ),
        "jwt_manipulation_probe": _try_import(
            "jwt_manipulation_probe",
            "src.analysis.active.injection.jwt_manipulation",
            "jwt_manipulation_probe",
        ),
        "ldap_injection_active_probe": _try_import(
            "ldap_injection_active_probe",
            "src.analysis.active.injection.ldap",
            "ldap_injection_active_probe",
        ),
        "nosql_injection_probe": _try_import(
            "nosql_injection_probe",
            "src.analysis.active.injection.nosql",
            "nosql_injection_probe",
        ),
        "open_redirect_active_probe": _try_import(
            "open_redirect_active_probe",
            "src.analysis.active.injection.open_redirect",
            "open_redirect_active_probe",
        ),
        "path_traversal_active_probe": _try_import(
            "path_traversal_active_probe",
            "src.analysis.active.injection.path_traversal",
            "path_traversal_active_probe",
        ),
        "proxy_ssrf_probe": _try_import(
            "proxy_ssrf_probe",
            "src.analysis.active.injection.proxy_ssrf",
            "proxy_ssrf_probe",
        ),
        "ssrf_active_probe": _try_import(
            "ssrf_active_probe",
            "src.analysis.active.injection.ssrf",
            "ssrf_active_probe",
        ),
        "ssti_active_probe": _try_import(
            "ssti_active_probe",
            "src.analysis.active.injection.ssti",
            "ssti_active_probe",
        ),
        "xpath_injection_active_probe": _try_import(
            "xpath_injection_active_probe",
            "src.analysis.active.injection.xpath",
            "xpath_injection_active_probe",
        ),
        "xss_reflect_probe": _try_import(
            "xss_reflect_probe",
            "src.analysis.active.injection.xss_reflect_probe",
            "xss_reflect_probe",
        ),
        "xxe_active_probe": _try_import(
            "xxe_active_probe",
            "src.analysis.active.injection.xxe",
            "xxe_active_probe",
        ),
        "run_jwt_attack_suite": _try_import(
            "run_jwt_attack_suite",
            "src.analysis.active.jwt_attacks",
            "run_jwt_attack_suite",
        ),
        "jwt_token_regex": _try_import(
            "jwt_token_regex",
            "src.analysis.active.jwt_attacks.jwt_attack_helpers",
            "JWT_RE",
        ),
        "hidden_parameter_miner": _try_import(
            "hidden_parameter_miner",
            "src.analysis.active.param_mining",
            "param_mining_probe",
        ),
        "race_condition_probe": _try_import(
            "race_condition_probe",
            "src.analysis.active.race_condition",
            "race_condition_probe",
        ),
        "run_mutation_tests": _try_import(
            "run_mutation_tests",
            "src.analysis.intelligence.mutation_runtime",
            "run_mutation_tests",
        ),
        "filter_parameter_fuzzer": _try_import(
            "filter_parameter_fuzzer",
            "src.analysis.json.active_probes",
            "filter_parameter_fuzzer",
        ),
        "pagination_walker": _try_import(
            "pagination_walker",
            "src.analysis.json.active_probes",
            "pagination_walker",
        ),
        "parameter_dependency_tracker": _try_import(
            "parameter_dependency_tracker",
            "src.analysis.json.active_probes",
            "parameter_dependency_tracker",
        ),
        "state_transition_analyzer": _try_import(
            "state_transition_analyzer",
            "src.analysis.json.active_probes",
            "state_transition_analyzer",
        ),
        "response_diff_engine": _try_import(
            "response_diff_engine",
            "src.analysis.response._core.response_analysis._diff_engine",
            "response_diff_engine",
        ),
        "generate_payload_suggestions": _try_import(
            "generate_payload_suggestions",
            "src.fuzzing.payload_generator",
            "generate_payload_suggestions",
        ),
        "generate_header_payloads": _try_import(
            "generate_header_payloads",
            "src.fuzzing.payload_generator_http",
            "generate_header_payloads",
        ),
        "generate_body_payloads": _try_import(
            "generate_body_payloads",
            "src.fuzzing.payload_generator_http",
            "generate_body_payloads",
        ),
    }

    from src.pipeline.services.pipeline_orchestrator.stages.probe_runners import (
        _run_fuzzing_campaign_probe,
    )

    probes["run_fuzzing_campaign_probe"] = _run_fuzzing_campaign_probe
    probes["_active_check_manifests"] = DEFAULT_ACTIVE_MANIFEST_REGISTRY.all()
    return probes


# Backward-compat shim: prior revisions of this function were
# ``@functools.lru_cache(maxsize=1)``-decorated. Several call-sites
# (and the ``test_active_scan_import_contract`` test) call
# ``_load_active_probe_functions.cache_clear()`` to force a rebuild.
# The function is now plain (each call rebuilds the dict) so the
# method is a no-op retained for API compatibility.
def _clear_probe_registry_cache() -> None:  # pragma: no cover - trivial
    return None


_load_active_probe_functions.cache_clear = _clear_probe_registry_cache  # type: ignore[attr-defined]
