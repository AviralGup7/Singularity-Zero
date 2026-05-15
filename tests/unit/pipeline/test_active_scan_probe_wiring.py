import asyncio
import re
from collections.abc import Awaitable, Callable
from typing import cast

import pytest

from src.core.models.stage_result import PipelineContext
from src.pipeline.services.pipeline_orchestrator.stages import active_scan


class _DummyResponseCache:
    def prefetch(self, targets: list[str]) -> list[dict[str, object]]:
        _ = targets
        return []

    def get(self, target: str) -> dict[str, object]:
        _ = target
        return {}


def _noop_emit_progress(*args: object, **kwargs: object) -> None:
    _ = (args, kwargs)


@pytest.mark.asyncio
async def test_active_scan_wires_response_cache_to_cache_dependent_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: dict[str, tuple[tuple[object, ...], dict[str, object]]] = {}

    def _probe(name: str):
        def _inner(*args: object, **kwargs: object) -> list[dict[str, object]]:
            calls[name] = (args, kwargs)
            return []

        return _inner

    probe_names = [
        "sqli",
        "csrf",
        "jwt",
        "xss",
        "ssrf",
        "file_upload",
        "oauth",
        "open_redirect",
        "path_traversal",
        "command_injection",
        "idor",
        "hpp",
        "websocket",
        "graphql",
        "xpath",
        "ssti",
        "xxe",
        "nosql",
        "auth_bypass",
        "jwt_attacks",
        "ldap",
        "deserialization",
        "proxy_ssrf",
        "host_header",
        "crlf",
        "mutation",
        "fuzz_param",
        "fuzz_header",
        "fuzz_body",
        "json_state_transition",
        "json_parameter_dependency",
        "json_pagination",
        "json_filter_fuzz",
        "response_diff",
        "cors",
        "trace",
        "options",
        "cloud_metadata",
        "http_smuggling_low",
        "http_smuggling_h2",
    ]

    def _auth_suite(*args: object, **kwargs: object) -> dict[str, list[dict[str, object]]]:
        calls["auth_bypass"] = (args, kwargs)
        return {
            "jwt_stripping": [],
            "cookie_manipulation": [],
            "auth_bypass_patterns": [],
            "credential_stuffing": [],
            "mfa_bypass": [],
            "password_reset_abuse": [],
        }

    def _jwt_suite(*args: object, **kwargs: object) -> dict[str, object]:
        calls["jwt_attacks"] = (args, kwargs)
        return {
            "vulnerable_attacks": 0,
            "vulnerable_list": [],
            "severity": "info",
            "token_preview": "",
        }

    probes = {
        "run_auth_bypass_probes": _auth_suite,
        "sqli_safe_probe": _probe("sqli"),
        "csrf_active_probe": _probe("csrf"),
        "jwt_manipulation_probe": _probe("jwt"),
        "xss_reflect_probe": _probe("xss"),
        "ssrf_active_probe": _probe("ssrf"),
        "file_upload_active_probe": _probe("file_upload"),
        "oauth_flow_analyzer": _probe("oauth"),
        "open_redirect_active_probe": _probe("open_redirect"),
        "path_traversal_active_probe": _probe("path_traversal"),
        "command_injection_active_probe": _probe("command_injection"),
        "idor_active_probe": _probe("idor"),
        "hpp_active_probe": _probe("hpp"),
        "websocket_message_probe": _probe("websocket"),
        "graphql_active_probe": _probe("graphql"),
        "xpath_injection_active_probe": _probe("xpath"),
        "ssti_active_probe": _probe("ssti"),
        "xxe_active_probe": _probe("xxe"),
        "nosql_injection_probe": _probe("nosql"),
        "run_jwt_attack_suite": _jwt_suite,
        "jwt_token_regex": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "ldap_injection_active_probe": _probe("ldap"),
        "deserialization_probe": _probe("deserialization"),
        "proxy_ssrf_probe": _probe("proxy_ssrf"),
        "host_header_injection_probe": _probe("host_header"),
        "crlf_injection_probe": _probe("crlf"),
        "run_mutation_tests": _probe("mutation"),
        "generate_payload_suggestions": _probe("fuzz_param"),
        "generate_header_payloads": _probe("fuzz_header"),
        "generate_body_payloads": _probe("fuzz_body"),
        "state_transition_analyzer": _probe("json_state_transition"),
        "parameter_dependency_tracker": _probe("json_parameter_dependency"),
        "pagination_walker": _probe("json_pagination"),
        "filter_parameter_fuzzer": _probe("json_filter_fuzz"),
        "response_diff_engine": _probe("response_diff"),
        "cors_preflight_probe": _probe("cors"),
        "trace_method_probe": _probe("trace"),
        "options_method_probe": _probe("options"),
        "cloud_metadata_active_probe": _probe("cloud_metadata"),
        "http_smuggling_probe": _probe("http_smuggling_low"),
        "http2_probe": _probe("http_smuggling_h2"),
    }

    cache = _DummyResponseCache()
    monkeypatch.setattr(active_scan, "_load_active_probe_functions", lambda: probes)
    monkeypatch.setattr(active_scan, "_build_response_cache", lambda: cache)
    monkeypatch.setattr(active_scan, "emit_progress", _noop_emit_progress)

    ctx = PipelineContext()
    ctx.result.live_hosts = {"api.example.com"}
    ctx.result.urls = {
        "https://api.example.com/users?id=1&token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
    }
    ctx.result.selected_priority_items = [
        {"url": "https://api.example.com/admin?user_id=1", "score": 0.9}
    ]

    output = await active_scan.run_active_scanning(args=None, config=None, ctx=ctx)

    for name in probe_names:
        assert name in calls

    dict_target_cache_probes = [
        "sqli",
        "csrf",
        "jwt",
        "xss",
        "ssrf",
        "file_upload",
        "oauth",
        "open_redirect",
        "path_traversal",
        "command_injection",
        "idor",
        "hpp",
        "websocket",
        "graphql",
        "xpath",
        "ssti",
        "xxe",
        "nosql",
        "ldap",
        "deserialization",
        "proxy_ssrf",
        "host_header",
        "crlf",
        "cors",
        "trace",
        "options",
        "http_smuggling_low",
        "http_smuggling_h2",
    ]
    for name in dict_target_cache_probes:
        args, _ = calls[name]
        assert len(args) >= 2
        assert args[1] is cache
        assert isinstance(args[0], list)
        target_items = cast(list[dict[str, object]], args[0])
        assert all("url" in item for item in target_items)

    list_target_cache_probes = [
        "json_state_transition",
        "json_parameter_dependency",
        "json_pagination",
        "json_filter_fuzz",
        "response_diff",
    ]
    for name in list_target_cache_probes:
        args, _ = calls[name]
        assert len(args) >= 2
        assert args[1] is cache
        assert isinstance(args[0], list)
        urls = cast(list[str], args[0])
        assert all(isinstance(item, str) for item in urls)

    auth_args, _ = calls["auth_bypass"]
    assert len(auth_args) >= 2
    assert auth_args[1] is cache

    jwt_args, _ = calls["jwt_attacks"]
    assert len(jwt_args) >= 2
    assert isinstance(jwt_args[0], str)
    assert isinstance(jwt_args[1], str)

    assert output.metrics["probes_failed"] == 0


@pytest.mark.asyncio
async def test_try_probe_timeout_returns_failed_without_raising() -> None:
    import time

    def _slow_probe() -> list[dict[str, object]]:
        time.sleep(0.2)
        return [{"ok": True}]

    try_probe = cast(
        Callable[..., Awaitable[tuple[str, list[dict[str, object]], bool]]],
        getattr(active_scan, "_try_probe"),
    )

    name, findings, ok = await try_probe(
        "slow_probe",
        _slow_probe,
        timeout_seconds=0.01,
    )

    assert name == "slow_probe"
    assert findings == []
    assert ok is False


@pytest.mark.asyncio
async def test_try_probe_supports_async_probe_functions() -> None:
    async def _async_probe() -> list[dict[str, object]]:
        await asyncio.sleep(0)
        return [{"url": "https://example.com", "severity": "low"}]

    try_probe = cast(
        Callable[..., Awaitable[tuple[str, list[dict[str, object]], bool]]],
        getattr(active_scan, "_try_probe"),
    )

    name, findings, ok = await try_probe(
        "async_probe",
        _async_probe,
        timeout_seconds=1.0,
    )

    assert name == "async_probe"
    assert ok is True
    assert findings == [{"url": "https://example.com", "severity": "low"}]


@pytest.mark.asyncio
async def test_try_probe_awaits_awaitable_results_from_sync_probe() -> None:
    def _sync_probe_returning_coroutine() -> Awaitable[list[dict[str, object]]]:
        async def _inner() -> list[dict[str, object]]:
            await asyncio.sleep(0)
            return [{"url": "https://example.com/api", "severity": "medium"}]

        return _inner()

    try_probe = cast(
        Callable[..., Awaitable[tuple[str, list[dict[str, object]], bool]]],
        getattr(active_scan, "_try_probe"),
    )

    name, findings, ok = await try_probe(
        "awaitable_sync_probe",
        _sync_probe_returning_coroutine,
        timeout_seconds=1.0,
    )

    assert name == "awaitable_sync_probe"
    assert ok is True
    assert findings == [{"url": "https://example.com/api", "severity": "medium"}]
