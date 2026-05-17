import argparse
import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.models.stage_result import PipelineContext, StageResult


class TestStageIsolationContracts:
    """Contract test: stage wrappers must not mutate PipelineContext.result directly."""

    @pytest.mark.asyncio
    async def test_active_scan_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import active_scan as active_stage

        ctx = PipelineContext(
            result=StageResult(
                scope_entries=["api.example.com"],
                started_at=asyncio.get_event_loop().time(),
            )
        )
        ctx.result.selected_priority_items = [{"url": "https://api.example.com/login"}]

        # Setup mock probes that return findings
        mock_finding = {
            "url": "https://api.example.com/login",
            "severity": "high",
            "confidence": 0.9,
        }

        async def _mock_sqli(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            return [mock_finding]

        async def _mock_noop(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            return []

        # List of all required keys in mock_probes dictionary in active_scan.py
        mock_probes = {
            "sqli_safe_probe": _mock_sqli,
            "csrf_active_probe": _mock_noop,
            "jwt_manipulation_probe": _mock_noop,
            "xss_reflect_probe": _mock_noop,
            "ssrf_active_probe": _mock_noop,
            "file_upload_active_probe": _mock_noop,
            "oauth_flow_analyzer": _mock_noop,
            "open_redirect_active_probe": _mock_noop,
            "path_traversal_active_probe": _mock_noop,
            "command_injection_active_probe": _mock_noop,
            "idor_active_probe": _mock_noop,
            "hpp_active_probe": _mock_noop,
            "websocket_message_probe": _mock_noop,
            "graphql_active_probe": _mock_noop,
            "xpath_injection_active_probe": _mock_noop,
            "ssti_active_probe": _mock_noop,
            "xxe_active_probe": _mock_noop,
            "nosql_injection_probe": _mock_noop,
            "run_auth_bypass_probes": lambda *a, **k: {},
            "run_jwt_attack_suite": lambda *a, **k: {},
            "jwt_token_regex": None,
            "ldap_injection_active_probe": _mock_noop,
            "deserialization_probe": _mock_noop,
            "proxy_ssrf_probe": _mock_noop,
            "host_header_injection_probe": _mock_noop,
            "crlf_injection_probe": _mock_noop,
            "run_mutation_tests": _mock_noop,
            "generate_payload_suggestions": lambda *a, **k: [],
            "generate_header_payloads": lambda *a, **k: [],
            "generate_body_payloads": lambda *a, **k: [],
            "response_diff_engine": _mock_noop,
            "cors_preflight_probe": _mock_noop,
            "trace_method_probe": _mock_noop,
            "options_method_probe": _mock_noop,
            "cloud_metadata_active_probe": _mock_noop,
            "http_smuggling_probe": lambda *a, **k: [],
            "http2_probe": lambda *a, **k: [],
        }

        config = argparse.Namespace(
            analysis={"adaptive_mode": "false", "active_probe_timeout_seconds": 10},
            target_name="example",
        )

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(active_stage, "_load_active_probe_functions", lambda: mock_probes)
            mp.setattr(active_stage, "emit_progress", lambda *a, **k: None)

            output = await active_stage.run_active_scanning(args=None, config=config, ctx=ctx)

            # 1. Output must contain the delta
            assert "active_scan_findings" in output.state_delta
            findings = output.state_delta["active_scan_findings"]
            assert len(findings) > 0
            assert findings[0]["severity"] == "high"

            # 2. Result in ctx MUST NOT be updated yet (isolation)
            assert len(ctx.result.reportable_findings) == 0

    @pytest.mark.asyncio
    async def test_recon_isolation(self) -> None:
        from src.pipeline.services.pipeline_orchestrator.stages import recon as recon_stage

        ctx = PipelineContext(
            result=StageResult(
                scope_entries=["example.com"],
                started_at=asyncio.get_event_loop().time(),
            )
        )
        # Mock output store
        ctx.output_store = AsyncMock()

        async def _mock_subdomains_service(*args: Any, **kwargs: Any) -> StageOutput:
            return StageOutput(
                stage_name="subdomains",
                outcome=StageOutcome.COMPLETED,
                duration_seconds=0.1,
                state_delta={"subdomains": ["sub1.example.com"]},
            )

        config = argparse.Namespace(
            target_name="example",
            output_dir="/tmp",
            output={},
            tools={"subfinder": True},
            filters={},
            analysis={},
            scoring={},
        )

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(recon_stage, "run_subdomain_enumeration_service", _mock_subdomains_service)
            mp.setattr(recon_stage, "emit_progress", lambda *a, **k: None)

            output = await recon_stage.run_subdomain_enumeration(args=None, config=config, ctx=ctx)

            # 1. Delta contains the work
            assert "subdomains" in output.state_delta
            assert "sub1.example.com" in output.state_delta["subdomains"]

            # 2. Context was NOT updated (isolation)
            actual_subdomains = ctx.result.subdomains
            if hasattr(actual_subdomains, "to_set"):
                actual_subdomains = actual_subdomains.to_set()
            assert "sub1.example.com" not in actual_subdomains
