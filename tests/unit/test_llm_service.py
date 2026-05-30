"""Unit tests for the LLM Service Plane and its FastAPI routes.

Verifies the mock provider engine, exception failover recovery to rule-based security templates,
and FastAPI endpoint execution under strict tenant boundaries.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from src.intelligence.ml.llm_service import LLMConfig, LLMService


@pytest.fixture
def mock_finding() -> dict[str, Any]:
    return {
        "id": "test-finding-101",
        "title": "SQL Injection Candidate",
        "category": "sql_injection",
        "severity": "critical",
        "url": "https://api.example.com/v1/users?id=1",
        "evidence": "parameter 'id' is vulnerable to union-based injection",
        "description": "Leaked database syntax errors during scan.",
    }


@pytest.fixture
def mock_findings_list(mock_finding) -> list[dict[str, Any]]:
    return [
        mock_finding,
        {
            "id": "test-finding-102",
            "title": "Insecure Direct Object Reference",
            "category": "idor",
            "severity": "high",
            "url": "https://api.example.com/v1/records/42",
            "evidence": "response contains secret of another user",
            "description": "Validation checks bypassed.",
        },
    ]


@pytest.mark.anyio
async def test_llm_config_parsing() -> None:
    """Verify LLMConfig initializes correctly with defaults."""
    cfg = LLMConfig()
    assert not cfg.enabled
    assert cfg.provider == "mock"
    assert cfg.model == "gpt-4o"
    assert cfg.timeout_seconds == 10.0


@pytest.mark.anyio
async def test_llm_service_mock_explain(mock_finding) -> None:
    """Verify that Mock provider explain_finding generates dual-persona explanations."""
    service = LLMService(LLMConfig(enabled=True, provider="mock"))
    explanation = await service.explain_finding(mock_finding)

    assert "developer" in explanation
    assert "auditor" in explanation
    assert "SQL" in explanation["developer"]
    assert "NIST" in explanation["auditor"]


@pytest.mark.anyio
async def test_llm_service_mock_patch(mock_finding) -> None:
    """Verify secure patch generation on mock stack detection."""
    service = LLMService(LLMConfig(enabled=True, provider="mock"))
    patch = await service.generate_patch(mock_finding)

    assert patch["language"] == "python"
    assert "execute" in patch["remediation_code"]
    assert "secure" in patch["title"].lower() or "parameter" in patch["title"].lower()


@pytest.mark.anyio
async def test_llm_service_mock_triage(mock_finding) -> None:
    """Verify automated false positive review decisions and confidence scoring."""
    service = LLMService(LLMConfig(enabled=True, provider="mock"))
    review = await service.triage_false_positive(
        mock_finding, response_body="traceback error in line 42"
    )

    assert review["decision"] == "TP"
    assert review["confidence"] >= 0.80
    assert "stack trace" in review["reasoning"].lower()


@pytest.mark.anyio
async def test_llm_service_mock_executive_summary(mock_findings_list) -> None:
    """Verify comprehensive executive summary markdown generation."""
    service = LLMService(LLMConfig(enabled=True, provider="mock"))
    summary = await service.generate_executive_summary(mock_findings_list)

    assert "# Executive" in summary
    assert "Posture" in summary
    assert "Critical" in summary
    assert "SLA" in summary


@pytest.mark.anyio
async def test_llm_service_failover_graceful(mock_finding) -> None:
    """Verify bad API setups fail over gracefully to rule-based security templates."""
    # Configure an active OpenAI provider with a broken API URL to trigger exception
    bad_config = LLMConfig(
        enabled=True,
        provider="openai",
        api_base="https://localhost:9999/broken/endpoint",
        timeout_seconds=0.1,
    )
    service = LLMService(bad_config)

    # Test explain fallback
    explanation = await service.explain_finding(mock_finding)
    assert "developer" in explanation
    assert "auditor" in explanation
    assert "SI-10" in explanation["auditor"]  # Fallback NIST reference

    # Test patch fallback
    patch = await service.generate_patch(mock_finding)
    assert patch["language"] == "python"
    assert "execute" in patch["remediation_code"]

    # Test triage fallback
    review = await service.triage_false_positive(mock_finding)
    assert review["decision"] in ("TP", "FP")
    assert review["confidence"] >= 0.5

    # Test executive summary fallback
    summary = await service.generate_executive_summary([mock_finding])
    assert "# Executive" in summary


def test_fastapi_explain_route(tmp_path: Path, mock_finding) -> None:
    """Verify FastAPI GET /api/findings/{finding_id}/ai-explain endpoint executes cleanly."""
    from src.dashboard.fastapi.app import create_app
    from src.dashboard.fastapi.dependencies import get_queue_client

    # Scaffold mock target directory with findings.json
    target_dir = tmp_path / "api.example.com"
    target_dir.mkdir()
    run_dir = target_dir / "run-2026-05-29"
    run_dir.mkdir()

    findings_file = run_dir / "findings.json"
    finding_to_write = dict(mock_finding)
    finding_to_write["id"] = "api.example.com-run-2026-05-29-1"
    findings_file.write_text(json.dumps([finding_to_write]), encoding="utf-8")

    summary_file = run_dir / "run_summary.json"
    summary_file.write_text(
        json.dumps({"generated_at_utc": "2026-05-29T00:00:00Z"}), encoding="utf-8"
    )

    class MockQuery:
        output_root = tmp_path

    class MockQueueClient:
        query = MockQuery()

        def get_job(self, *args, **kwargs):
            return None

        def list_jobs(self, *args, **kwargs):
            return []

    # Create app and override dependencies
    app = create_app()
    app.state.config = type("Config", (), {"output_root": tmp_path})()

    # Enable LLM mock service
    from src.intelligence.ml.llm_service import LLMConfig, LLMService

    LLMService._instance = LLMService(LLMConfig(enabled=True, provider="mock"))

    app.dependency_overrides[get_queue_client] = lambda: MockQueueClient()

    client = TestClient(app)

    # Authenticate and query finding with correct tenant scoping
    headers = {"X-Tenant-ID": "default"}
    resp = client.get("/api/findings/api.example.com-run-2026-05-29-1/ai-explain", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["finding_id"] == "api.example.com-run-2026-05-29-1"
    assert "explanations" in data
    assert "developer" in data["explanations"]


def test_fastapi_triage_review_route(tmp_path: Path, mock_finding) -> None:
    """Verify FastAPI POST /api/triage/runs/{run_id}/findings/{finding_id}/ai-review."""
    from src.dashboard.fastapi.app import create_app
    from src.dashboard.fastapi.dependencies import get_queue_client

    target_dir = tmp_path / "api.example.com"
    target_dir.mkdir()
    run_dir = target_dir / "run-2026-05-29"
    run_dir.mkdir()

    findings_file = run_dir / "findings.json"
    finding_to_write = dict(mock_finding)
    finding_to_write["id"] = "api.example.com-run-2026-05-29-1"
    findings_file.write_text(json.dumps([finding_to_write]), encoding="utf-8")

    summary_file = run_dir / "run_summary.json"
    summary_file.write_text(
        json.dumps({"generated_at_utc": "2026-05-29T00:00:00Z"}), encoding="utf-8"
    )

    class MockQuery:
        output_root = tmp_path

    class MockQueueClient:
        query = MockQuery()

    app = create_app()
    app.state.config = type("Config", (), {"output_root": tmp_path})()
    app.dependency_overrides[get_queue_client] = lambda: MockQueueClient()

    # Enable LLM mock
    from src.intelligence.ml.llm_service import LLMConfig, LLMService

    LLMService._instance = LLMService(LLMConfig(enabled=True, provider="mock"))

    client = TestClient(app)

    # Post false-positive triage AI review
    resp = client.post(
        "/api/triage/runs/run-2026-05-29/findings/api.example.com-run-2026-05-29-1/ai-review",
        headers={"X-Tenant-ID": "default"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "review" in data
    assert data["review"]["decision"] in ("TP", "FP")
    assert "reasoning" in data["review"]


def test_fastapi_ai_summary_route(tmp_path: Path, mock_finding) -> None:
    """Verify FastAPI GET /api/reports/ai-summary and tenant-boundary scoping enforcement."""
    from src.dashboard.fastapi.app import create_app
    from src.dashboard.fastapi.dependencies import get_queue_client

    target_dir = tmp_path / "api.example.com"
    target_dir.mkdir()
    run_dir = target_dir / "run-2026-05-29"
    run_dir.mkdir()

    findings_file = run_dir / "findings.json"
    findings_file.write_text(json.dumps([mock_finding]), encoding="utf-8")

    summary_file = run_dir / "run_summary.json"
    summary_file.write_text(
        json.dumps({"generated_at_utc": "2026-05-29T00:00:00Z"}), encoding="utf-8"
    )

    class MockQuery:
        output_root = tmp_path

    class MockQueueClient:
        query = MockQuery()

    app = create_app()
    app.state.config = type("Config", (), {"output_root": tmp_path})()
    app.dependency_overrides[get_queue_client] = lambda: MockQueueClient()

    # Enable LLM mock
    from src.intelligence.ml.llm_service import LLMConfig, LLMService

    LLMService._instance = LLMService(LLMConfig(enabled=True, provider="mock"))

    client = TestClient(app)

    # Case A: Success Query under allowed tenant scope
    resp = client.get(
        "/api/reports/ai-summary?target=api.example.com",
        headers={"X-Tenant-ID": "default"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["target"] == "api.example.com"
    assert "summary" in data
    assert "# Executive" in data["summary"]

    # Case B: Multi-tenant boundary rejection - client_beta requests api.example.com
    # In creating the app, targets are scoped by checking is_target_owned_by_tenant()
    # Let's assert that a mismatching tenant ID results in 403 Forbidden
    resp_bad = client.get(
        "/api/reports/ai-summary?target=api.example.com",
        headers={"X-Tenant-ID": "client_beta"},
    )
    assert resp_bad.status_code == 403
