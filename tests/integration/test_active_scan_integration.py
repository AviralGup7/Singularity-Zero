"""
Integration tests for the Active Scanning stage.
Asserts that degraded_probes is correctly populated under timeout conditions.
"""

import asyncio
import re
from types import SimpleNamespace
from typing import Any, cast

import pytest

from src.core.models.stage_result import PipelineContext, StageResult
from src.pipeline.services.pipeline_orchestrator.stages import active_scan


@pytest.mark.asyncio
async def test_active_scan_degraded_probes_populated_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that degraded_probes is populated with timed-out probe info."""
    # 1. Setup a minimal context
    ctx = PipelineContext(
        result=StageResult(
            scope_entries=["api.example.com"],
            started_at=asyncio.get_event_loop().time(),
        )
    )
    ctx.result.selected_priority_items = [
        {"url": "https://api.example.com/admin?user_id=1", "score": 0.9}
    ]

    # 2. Setup mock probe functions
    # We want one probe (e.g. sqli_safe_probe) to raise TimeoutError to simulate timeout.
    calls: dict[str, int] = {}

    def create_mock_probe(name: str, should_timeout: bool = False) -> Any:
        async def _probe(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            calls[name] = calls.get(name, 0) + 1
            if should_timeout:
                raise TimeoutError(f"Simulated timeout for {name}")
            return []
        return _probe

    mock_probes = {
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
    }

    # Apply monkeypatches to avoid running adaptive mode and load our mock probes
    monkeypatch.setattr(active_scan, "_load_active_probe_functions", lambda: mock_probes)
    monkeypatch.setattr(active_scan, "emit_progress", lambda *a, **k: None)

    # Disable adaptive mode to run standard run_active_scanning
    config = SimpleNamespace(
        analysis={
            "adaptive_mode": "false",
            "active_probe_timeout_seconds": 1,
        }
    )

    # 3. Execution
    stage_output = await active_scan.run_active_scanning(
        args=None,
        config=config,
        ctx=ctx,
    )

    # 4. Assertions
    assert stage_output is not None
    assert stage_output.metrics is not None
    metrics = stage_output.metrics

    # Check that degraded_probes exists in metrics
    assert "degraded_probes" in metrics
    degraded_probes = metrics["degraded_probes"]

    # Verify our timed out sqli probe is listed in degraded_probes
    sqli_timeouts = [
        dict(item) for item in cast(Any, degraded_probes)
        if dict(item).get("probe") == "sqli" and dict(item).get("reason") == "timeout"
    ]
    assert len(sqli_timeouts) == 1
    assert "timed out after" in sqli_timeouts[0].get("message", "")
