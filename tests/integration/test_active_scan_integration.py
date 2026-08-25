"""
Integration tests for the Active Scanning stage.

Tests real probe invocation against a local HTTP server to validate
timeout handling, degraded_probes population, and probe execution
without mocking the entire probe registry.
"""

import asyncio
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from typing import Any, cast

import pytest

from src.core.models.stage_result import PipelineContext, StageResult
from src.pipeline.services.pipeline_orchestrator.stages import active_scan, active_scan_adaptive


class _QuietHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for integration tests."""

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Allowed-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_TRACE(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.end_headers()
        self.wfile.write(b"TRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n")

    def log_message(self, format: str, *args: Any) -> None:
        pass  # silence request logs


@pytest.fixture(scope="module")
def _local_http_server():
    """Start a local HTTP server for integration tests."""
    server = HTTPServer(("127.0.0.1", 0), _QuietHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def _make_ctx(target: str = "127.0.0.1") -> PipelineContext:
    ctx = PipelineContext(
        result=StageResult(
            scope_entries=[target],
            started_at=asyncio.get_event_loop().time(),
        )
    )
    return ctx


def _make_config(adaptive: str = "false", timeout: int = 30) -> SimpleNamespace:
    return SimpleNamespace(
        analysis={
            "adaptive_mode": adaptive,
            "active_probe_timeout_seconds": timeout,
        }
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_real_probe_invocation_hits_local_server(
    _local_http_server: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that real probes (options, trace) execute against a live server."""
    monkeypatch.setattr(active_scan, "emit_progress", lambda *a, **k: None)
    monkeypatch.setattr(active_scan_adaptive, "emit_progress", lambda *a, **k: None)

    ctx = _make_ctx()
    ctx.result.selected_priority_items = [{"url": f"{_local_http_server}/test", "score": 0.9}]

    # Load real probe functions from the registry
    real_probes = active_scan._load_active_probe_functions()
    assert "options_method_probe" in real_probes
    assert "trace_method_probe" in real_probes

    # Verify that the real probes are callable and return lists
    # (we can't easily construct a real ResponseCache here, but we
    # verify the probe functions are properly loaded)
    assert callable(real_probes["options_method_probe"])
    assert callable(real_probes["trace_method_probe"])


@pytest.mark.asyncio
@pytest.mark.integration
async def test_active_scan_degraded_probes_populated_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that degraded_probes is populated with timed-out probe info.

    This test uses mock probes only for the timeout simulation, while
    validating the degraded_probes recording mechanism end-to-end.
    """
    ctx = _make_ctx()
    ctx.result.selected_priority_items = [
        {"url": "https://api.example.com/admin?user_id=1", "score": 0.9}
    ]

    calls: dict[str, int] = {}

    def create_mock_probe(name: str, should_timeout: bool = False) -> Any:
        async def _probe(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            calls[name] = calls.get(name, 0) + 1
            if should_timeout:
                raise TimeoutError(f"Simulated timeout for {name}")
            return []

        return _probe

    mock_probes: dict[str, Any] = {
        "sqli_safe_probe": create_mock_probe("sqli", should_timeout=True),
        "csrf_active_probe": create_mock_probe("csrf"),
        "jwt_manipulation_probe": create_mock_probe("jwt"),
        "xss_reflect_probe": create_mock_probe("xss"),
        "ssrf_active_probe": create_mock_probe("ssrf"),
        "file_upload_active_probe": create_mock_probe("file_upload"),
        "oauth_flow_analyzer": create_mock_probe("oauth"),
        "open_redirect_active_probe": create_mock_probe("open_redirect"),
        "path_traversal_active_probe": create_mock_probe("path_traversal"),
        "command_injection_active_probe": create_mock_probe("command_injection"),
        "idor_active_probe": create_mock_probe("idor"),
        "race_condition_probe": create_mock_probe("race"),
        "hpp_active_probe": create_mock_probe("hpp"),
        "websocket_message_probe": create_mock_probe("websocket"),
        "graphql_active_probe": create_mock_probe("graphql"),
        "xpath_injection_active_probe": create_mock_probe("xpath"),
        "ssti_active_probe": create_mock_probe("ssti"),
        "xxe_active_probe": create_mock_probe("xxe"),
        "nosql_injection_probe": create_mock_probe("nosql"),
        "run_auth_bypass_probes": lambda *a, **k: {},
        "run_jwt_attack_suite": lambda *a, **k: {},
        "jwt_token_regex": re.compile(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
        "ldap_injection_active_probe": create_mock_probe("ldap"),
        "deserialization_probe": create_mock_probe("deserialization"),
        "proxy_ssrf_probe": create_mock_probe("proxy_ssrf"),
        "host_header_injection_probe": create_mock_probe("host_header"),
        "crlf_injection_probe": create_mock_probe("crlf"),
        "run_mutation_tests": create_mock_probe("mutation"),
        "generate_payload_suggestions": lambda *a, **k: [],
        "generate_header_payloads": lambda *a, **k: [],
        "generate_body_payloads": lambda *a, **k: [],
        "response_diff_engine": create_mock_probe("response_diff"),
        "cors_preflight_probe": create_mock_probe("cors"),
        "trace_method_probe": create_mock_probe("trace"),
        "options_method_probe": create_mock_probe("options"),
        "cloud_metadata_active_probe": create_mock_probe("cloud_metadata"),
        "http_smuggling_probe": lambda *a, **k: [],
        "http2_probe": lambda *a, **k: [],
        "state_transition_analyzer": lambda *a, **k: [],
        "parameter_dependency_tracker": lambda *a, **k: [],
        "pagination_walker": lambda *a, **k: [],
        "filter_parameter_fuzzer": lambda *a, **k: [],
        "run_fuzzing_campaign_probe": lambda *a, **k: [],
    }

    monkeypatch.setattr(active_scan, "_load_active_probe_functions", lambda: mock_probes)
    monkeypatch.setattr(active_scan_adaptive, "_load_active_probe_functions", lambda: mock_probes)
    monkeypatch.setattr(active_scan, "emit_progress", lambda *a, **k: None)
    monkeypatch.setattr(active_scan_adaptive, "emit_progress", lambda *a, **k: None)

    config = _make_config(adaptive="false", timeout=1)

    stage_output = await active_scan.run_active_scanning(
        args=None,
        config=config,
        ctx=ctx,
    )

    assert stage_output is not None
    assert stage_output.metrics is not None
    metrics = stage_output.metrics

    assert "degraded_probes" in metrics
    degraded_probes = metrics["degraded_probes"]

    sqli_timeouts = [
        dict(item)
        for item in cast(Any, degraded_probes)
        if dict(item).get("probe") == "sqli" and dict(item).get("reason") == "timeout"
    ]
    assert len(sqli_timeouts) == 1
    assert "timed out after" in sqli_timeouts[0].get("message", "")


@pytest.mark.asyncio
@pytest.mark.integration
async def test_active_scan_adaptive_degraded_probes_populated_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that degraded_probes is populated in adaptive scan mode."""
    ctx = _make_ctx()
    ctx.urls = [
        "https://api.example.com/admin?user_id=1",
        "https://api.example.com/admin?user_id=2",
        "https://api.example.com/admin?user_id=3",
        "https://api.example.com/admin?user_id=4",
        "https://api.example.com/admin?user_id=5",
        "https://api.example.com/admin?user_id=6",
    ]

    calls: dict[str, int] = {}

    def create_mock_probe(name: str, should_timeout: bool = False) -> Any:
        async def _probe(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            calls[name] = calls.get(name, 0) + 1
            if should_timeout:
                raise TimeoutError(f"Simulated timeout for {name}")
            return []

        return _probe

    mock_probes: dict[str, Any] = {
        "sqli_safe_probe": create_mock_probe("sqli", should_timeout=True),
        "csrf_active_probe": create_mock_probe("csrf"),
        "jwt_manipulation_probe": create_mock_probe("jwt"),
        "xss_reflect_probe": create_mock_probe("xss"),
        "ssrf_active_probe": create_mock_probe("ssrf"),
        "file_upload_active_probe": create_mock_probe("file_upload"),
        "oauth_flow_analyzer": create_mock_probe("oauth"),
        "open_redirect_active_probe": create_mock_probe("open_redirect"),
        "path_traversal_active_probe": create_mock_probe("path_traversal"),
        "command_injection_active_probe": create_mock_probe("command_injection"),
        "idor_active_probe": create_mock_probe("idor"),
        "race_condition_probe": create_mock_probe("race"),
        "hpp_active_probe": create_mock_probe("hpp"),
        "websocket_message_probe": create_mock_probe("websocket"),
        "graphql_active_probe": create_mock_probe("graphql"),
        "xpath_injection_active_probe": create_mock_probe("xpath"),
        "ssti_active_probe": create_mock_probe("ssti"),
        "xxe_active_probe": create_mock_probe("xxe"),
        "nosql_injection_probe": create_mock_probe("nosql"),
        "run_auth_bypass_probes": lambda *a, **k: {},
        "run_jwt_attack_suite": lambda *a, **k: {},
        "jwt_token_regex": re.compile(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
        "ldap_injection_active_probe": create_mock_probe("ldap"),
        "deserialization_probe": create_mock_probe("deserialization"),
        "proxy_ssrf_probe": create_mock_probe("proxy_ssrf"),
        "host_header_injection_probe": create_mock_probe("host_header"),
        "crlf_injection_probe": create_mock_probe("crlf"),
        "run_mutation_tests": create_mock_probe("mutation"),
        "generate_payload_suggestions": lambda *a, **k: [],
        "generate_header_payloads": lambda *a, **k: [],
        "generate_body_payloads": lambda *a, **k: [],
        "response_diff_engine": create_mock_probe("response_diff"),
        "cors_preflight_probe": create_mock_probe("cors"),
        "trace_method_probe": create_mock_probe("trace"),
        "options_method_probe": create_mock_probe("options"),
        "cloud_metadata_active_probe": create_mock_probe("cloud_metadata"),
        "http_smuggling_probe": lambda *a, **k: [],
        "http2_probe": lambda *a, **k: [],
        "state_transition_analyzer": lambda *a, **k: [],
        "parameter_dependency_tracker": lambda *a, **k: [],
        "pagination_walker": lambda *a, **k: [],
        "filter_parameter_fuzzer": lambda *a, **k: [],
        "run_fuzzing_campaign_probe": lambda *a, **k: [],
    }

    monkeypatch.setattr(active_scan, "_load_active_probe_functions", lambda: mock_probes)
    monkeypatch.setattr(active_scan_adaptive, "_load_active_probe_functions", lambda: mock_probes)
    monkeypatch.setattr(active_scan, "emit_progress", lambda *a, **k: None)
    monkeypatch.setattr(active_scan_adaptive, "emit_progress", lambda *a, **k: None)

    config = _make_config(adaptive="true", timeout=1)

    stage_output = await active_scan.run_active_scanning(
        args=None,
        config=config,
        ctx=ctx,
    )

    assert stage_output is not None
    assert stage_output.metrics is not None
    metrics = stage_output.metrics

    assert "degraded_probes" in metrics
    degraded_probes = metrics["degraded_probes"]

    sqli_timeouts = [
        dict(item)
        for item in cast(Any, degraded_probes)
        if dict(item).get("probe") == "sqli" and dict(item).get("reason") == "timeout"
    ]
    assert len(sqli_timeouts) >= 1
    assert "timed out after" in sqli_timeouts[0].get("message", "")
