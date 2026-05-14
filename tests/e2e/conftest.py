import json
import os
import tempfile
from collections.abc import AsyncGenerator, Generator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8765"))


@pytest.fixture(scope="session")
def e2e_workspace() -> Generator[Path]:
    with tempfile.TemporaryDirectory() as tmp:
        workspace = Path(tmp)
        output_dir = workspace / "output"
        output_dir.mkdir()
        yield workspace


@pytest.fixture
def mock_target_server() -> Generator[dict[str, Any]]:
    mocks = {
        "enumerate_subdomains": MagicMock(),
        "probe_live_hosts": MagicMock(),
        "collect_urls": MagicMock(),
        "extract_parameters": MagicMock(),
        "rank_urls": MagicMock(),
        "run_passive_scanners": MagicMock(),
        "execute_validation_runtime": MagicMock(),
        "generate_run_report": MagicMock(),
        "build_dashboard_index": MagicMock(),
        "build_summary": MagicMock(),
        "capture_screenshots": MagicMock(),
        "merge_findings": MagicMock(),
        "filter_reportable_findings": MagicMock(),
        "build_artifact_diff": MagicMock(),
    }
    yield mocks


@pytest.fixture
def e2e_pipeline_config(e2e_workspace: Path) -> dict[str, Any]:
    return {
        "target_name": "e2e-test.example.com",
        "output_dir": str(e2e_workspace / "output"),
        "scope": ["e2e-test.example.com"],
        "concurrency": {"nuclei_workers": 1, "active_workers": 1},
        "output": {"dedupe_aliases": True, "write_artifact_manifest": True},
        "notifications": {"enabled": False, "channels": []},
        "tools": {"subfinder": True},
        "filters": {},
        "scoring": {},
        "mode": "quick",
        "analysis": {"max_iteration_limit": 1, "finding_feedback_limit": 5},
        "extensions": {},
        "review": {},
        "nuclei": {},
        "cache": {},
        "screenshots": {},
    }


@pytest.fixture
def e2e_scope_file(e2e_workspace: Path) -> Path:
    scope_file = e2e_workspace / "scope.txt"
    scope_file.write_text("e2e-test.example.com\n")
    return scope_file


@pytest.fixture
def e2e_config_file(e2e_workspace: Path, e2e_pipeline_config: dict[str, Any]) -> Path:
    config_file = e2e_workspace / "config.json"
    config_file.write_text(json.dumps(e2e_pipeline_config))
    return config_file


@pytest.fixture
def pipeline_runner(e2e_config_file: Path, e2e_scope_file: Path):
    from src.pipeline.services.pipeline_orchestrator import PipelineOrchestrator

    def _run(dry_run: bool = False) -> int:
        import argparse

        args = argparse.Namespace(
            config=str(e2e_config_file),
            scope=str(e2e_scope_file),
            dry_run=dry_run,
            skip_crtsh=True,
            refresh_cache=False,
        )
        orchestrator = PipelineOrchestrator()
        return orchestrator.run_sync(args)

    return _run


@pytest_asyncio.fixture
async def httpx_client() -> AsyncGenerator[httpx.AsyncClient]:
    pytest.importorskip("httpx")
    base_url = f"http://127.0.0.1:{DASHBOARD_PORT}"
    async with httpx.AsyncClient(base_url=base_url) as client:
        yield client


@pytest.fixture
def dashboard_config(e2e_workspace: Path):
    from src.dashboard.fastapi.config import DashboardConfig

    return DashboardConfig(
        host="127.0.0.1",
        port=8765,
        output_root=e2e_workspace / "output",
        workspace_root=e2e_workspace,
        frontend_dist=e2e_workspace / "frontend_dist",
        config_template=e2e_workspace / "config_template.json",
    )


@pytest.fixture
def mock_dashboard_services():
    with patch("src.dashboard.services.DashboardServices") as mock_services:
        mock_instance = MagicMock()
        mock_instance.list_jobs.return_value = []
        mock_instance.list_targets.return_value = []
        mock_instance.findings_summary.return_value = {
            "total_findings": 0,
            "severity_breakdown": {},
        }
        mock_instance.detection_gap_summary.return_value = {"empty_modules": []}
        mock_instance.api_defaults.return_value = {
            "form_defaults": {},
            "default_mode": "quick",
            "config_template": {},
        }
        mock_services.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def exploit_target():
    from src.exploitation.models import ExploitTarget

    return ExploitTarget(
        url="https://e2e-test.example.com/api/v1/users",
        method="GET",
        headers={"Content-Type": "application/json"},
        parameters={"id": "1"},
        finding_id="e2e-finding-001",
        risk_level="high",
        scope_validated=True,
    )


@pytest.fixture
def e2e_output_store(e2e_workspace: Path):
    from src.pipeline.services.output_store import PipelineOutputStore

    target_root = e2e_workspace / "output" / "e2e-test.example.com"
    target_root.mkdir(parents=True, exist_ok=True)
    run_dir = target_root / "run-e2e-001"
    run_dir.mkdir(parents=True, exist_ok=True)
    cache_root = target_root / ".cache"
    cache_root.mkdir(parents=True, exist_ok=True)

    store = PipelineOutputStore(
        target_root=target_root,
        run_dir=run_dir,
        dedupe_aliases=True,
        write_artifact_manifest=True,
    )
    return store
