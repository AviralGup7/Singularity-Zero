import json
from pathlib import Path

import pytest

from src.core.checkpoint import CheckpointManager, CheckpointState
from src.core.middleware import ScopeValidator


@pytest.fixture
def sample_nuclei_jsonl_line() -> str:
    """Return a single valid Nuclei JSONL line."""
    return json.dumps(
        {
            "template-id": "cves/2023/CVE-2023-1234.yaml",
            "matched-at": "https://example.com/vuln",
            "host": "https://example.com",
            "info": {
                "name": "Test Vulnerability",
                "severity": "high",
                "description": "A test vulnerability",
                "reference": ["https://example.com/ref"],
                "tags": ["cve", "xss"],
            },
            "classification": {
                "cve-id": ["CVE-2023-1234"],
                "cwe-id": ["CWE-79"],
            },
            "matcher-name": "body_match",
            "type": "http",
            "timestamp": "2024-01-01T00:00:00Z",
            "curl-command": "curl https://example.com/vuln",
            "ip": "93.184.216.34",
        }
    )


@pytest.fixture
def sample_nuclei_jsonl_multi(sample_nuclei_jsonl_line: str) -> str:
    """Return multiple Nuclei JSONL lines."""
    line2 = json.dumps(
        {
            "template-id": "technologies/tech-detect.yaml",
            "matched-at": "https://example.com/",
            "host": "https://example.com",
            "info": {
                "name": "Technology Detection",
                "severity": "info",
                "description": "Detected technology",
                "tags": ["tech-detect"],
            },
            "matcher-name": "header_match",
            "type": "http",
            "timestamp": "2024-01-01T00:00:01Z",
        }
    )
    return f"{sample_nuclei_jsonl_line}\n{line2}"


@pytest.fixture
def scope_validator() -> ScopeValidator:
    """Return a ScopeValidator with common test scope hosts."""
    return ScopeValidator(
        {
            "example.com",
            "*.api.example.com",
            "192.168.1.0/24",
            "10.0.0.1",
        }
    )


@pytest.fixture
def checkpoint_manager(tmp_path: Path) -> CheckpointManager:
    """Return a CheckpointManager backed by a temp directory."""
    return CheckpointManager(tmp_path / "checkpoints", "test-run-001")


@pytest.fixture
def checkpoint_state() -> CheckpointState:
    """Return a CheckpointState with test data."""
    return CheckpointState(
        pipeline_run_id="test-run-001",
        checkpoint_version=1,
        completed_stages=["scope", "subdomain_discovery"],
        current_stage="host_probing",
        stage_results={"scope": {"status": "completed"}},
        module_metrics={"scope_duration": 1.5},
    )
