import asyncio
import re
from collections.abc import Awaitable
from types import SimpleNamespace
from typing import Any

import pytest

from src.core.models.stage_result import PipelineContext, StageResult
from src.pipeline.services.pipeline_orchestrator.stages import active_scan


@pytest.mark.asyncio
async def test_active_scan_wires_response_cache_to_cache_dependent_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1. Setup minimal context
    ctx = PipelineContext(
        result=StageResult(
            scope_entries=["api.example.com"],
            started_at=asyncio.get_event_loop().time(),
        )
    )
    ctx.result.selected_priority_items = [
        {"url": "https://api.example.com/admin?user_id=1", "score": 0.9}
    ]

    # 2. Mock the dependency loading
    calls: dict[str, list[Any]] = {}

    def _mock_probe_factory(name: str):
        async def _probe(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            calls.setdefault(name, []).append((args, kwargs))
            return []

        return _probe

    # Probes that active_scan expects
    mock_probes = {
        "sqli_safe_probe": _mock_probe_factory("sqli"),
        "csrf_active_probe": _mock_probe_factory("csrf"),
        "jwt_manipulation_probe": _mock_probe_factory("jwt"),
        "xss_reflect_probe": _mock_probe_factory("xss"),
        "ssrf_active_probe": _mock_probe_factory("ssrf"),
        "file_upload_active_probe": _mock_probe_factory("file_upload"),
        "oauth_flow_analyzer": _mock_probe_factory("oauth"),
        "open_redirect_active_probe": _mock_probe_factory("open_redirect"),
        "path_traversal_active_probe": _mock_probe_factory("path_traversal"),
        "command_injection_active_probe": _mock_probe_factory("command_injection"),
        "idor_active_probe": _mock_probe_factory("idor"),
        "hpp_active_probe": _mock_probe_factory("hpp"),
        "websocket_message_probe": _mock_probe_factory("websocket"),
        "graphql_active_probe": _mock_probe_factory("graphql"),
        "xpath_injection_active_probe": _mock_probe_factory("xpath"),
        "ssti_active_probe": _mock_probe_factory("ssti"),
        "xxe_active_probe": _mock_probe_factory("xxe"),
        "nosql_injection_probe": _mock_probe_factory("nosql"),
        "run_auth_bypass_probes": lambda *a, **k: {},
        "run_jwt_attack_suite": lambda *a, **k: {},
        "jwt_token_regex": re.compile(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
        "ldap_injection_active_probe": _mock_probe_factory("ldap"),
        "deserialization_probe": _mock_probe_factory("deserialization"),
        "proxy_ssrf_probe": _mock_probe_factory("proxy_ssrf"),
        "host_header_injection_probe": _mock_probe_factory("host_header"),
        "crlf_injection_probe": _mock_probe_factory("crlf"),
        "run_mutation_tests": _mock_probe_factory("mutation"),
        "generate_payload_suggestions": lambda *a, **k: [],
        "generate_header_payloads": lambda *a, **k: [],
        "generate_body_payloads": lambda *a, **k: [],
        "response_diff_engine": _mock_probe_factory("response_diff"),
        "cors_preflight_probe": _mock_probe_factory("cors"),
        "trace_method_probe": _mock_probe_factory("trace"),
        "options_method_probe": _mock_probe_factory("options"),
        "cloud_metadata_active_probe": _mock_probe_factory("cloud_metadata"),
        "http_smuggling_probe": lambda *a, **k: [],
        "http2_probe": lambda *a, **k: [],
    }

    monkeypatch.setattr(active_scan, "_load_active_probe_functions", lambda: mock_probes)
    monkeypatch.setattr(active_scan, "emit_progress", lambda *a, **k: None)

    # 3. Execution
    config = SimpleNamespace(
        analysis={"adaptive_mode": "false", "active_probe_timeout_seconds": 180}
    )
    await active_scan.run_active_scanning(args=None, config=config, ctx=ctx)

    # 4. Verify sqli was called with the shared_response_cache
    assert "sqli" in calls
    args, kwargs = calls["sqli"][0]
    # args[0] is items, args[1] is response_cache
    assert hasattr(args[1], "get")


@pytest.mark.asyncio
async def test_try_probe_timeout_handling() -> None:
    async def _slow_probe(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        await asyncio.sleep(0.5)
        return [{"url": "http://slow", "severity": "low"}]

    name, findings, ok = await active_scan._try_probe(
        "slow_probe",
        _slow_probe,
        timeout_seconds=0.1,
    )

    assert name == "slow_probe"
    assert ok is False
    assert findings == []


@pytest.mark.asyncio
async def test_try_probe_exception_resilience() -> None:
    def _crash_probe(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        raise RuntimeError("BOOM")

    name, findings, ok = await active_scan._try_probe(
        "crash_probe",
        _crash_probe,
        timeout_seconds=1.0,
    )

    assert name == "crash_probe"
    assert ok is False
    assert findings == []


@pytest.mark.asyncio
async def test_try_probe_sync_to_async_wrapping() -> None:
    def _sync_probe(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        return [{"url": "https://example.com/api", "severity": "medium"}]

    name, findings, ok = await active_scan._try_probe(
        "sync_probe",
        _sync_probe,
        timeout_seconds=1.0,
    )

    assert name == "sync_probe"
    assert ok is True
    assert findings == [{"url": "https://example.com/api", "severity": "medium"}]


@pytest.mark.asyncio
async def test_try_probe_handles_awaitable_return() -> None:
    def _sync_probe_returning_coroutine(
        *_args: Any, **_kwargs: Any
    ) -> Awaitable[list[dict[str, Any]]]:
        async def _inner():
            return [{"url": "https://example.com/api", "severity": "medium"}]

        return _inner()

    name, findings, ok = await active_scan._try_probe(
        "awaitable_sync_probe",
        _sync_probe_returning_coroutine,
        timeout_seconds=1.0,
    )

    assert name == "awaitable_sync_probe"
    assert ok is True
    assert findings == [{"url": "https://example.com/api", "severity": "medium"}]
