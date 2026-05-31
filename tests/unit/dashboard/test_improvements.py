import json
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from src.dashboard.fastapi.app import create_app
from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.routers.findings import _find_finding_by_id


def test_dashboard_stats_caching(tmp_path: Path) -> None:
    config = DashboardConfig(
        output_root=tmp_path,
        workspace_root=tmp_path,
        cache_db_path=str(tmp_path / "cache.db"),
        cache_dir=str(tmp_path / "cache_layer"),
    )
    app = create_app(config)

    with TestClient(app) as client:
        # Mock list_targets and list_jobs after lifespan startup has initialized state.services
        app.state.services.list_targets = MagicMock(
            return_value=[{"severity_counts": {"critical": 2}}]
        )
        app.state.services.list_jobs = MagicMock(return_value=[])

        # First call calculates and caches
        resp1 = client.get("/api/dashboard")
        assert resp1.status_code == 200
        assert resp1.json()["total_findings"] == 2
        assert app.state.services.list_targets.call_count == 1

        # Second call should hit the cache (TTL = 5s)
        resp2 = client.get("/api/dashboard")
        assert resp2.status_code == 200
        assert resp2.json()["total_findings"] == 2
        assert app.state.services.list_targets.call_count == 1


def test_request_id_tracing(tmp_path: Path) -> None:
    config = DashboardConfig(
        output_root=tmp_path,
        workspace_root=tmp_path,
        cache_db_path=str(tmp_path / "cache.db"),
        cache_dir=str(tmp_path / "cache_layer"),
    )
    app = create_app(config)

    with TestClient(app) as client:
        resp = client.get("/api/version")
        assert resp.status_code == 200
        assert "X-Request-ID" in resp.headers
        assert "X-Process-Time" in resp.headers


def test_metrics_endpoint(tmp_path: Path) -> None:
    config = DashboardConfig(
        output_root=tmp_path,
        workspace_root=tmp_path,
        cache_db_path=str(tmp_path / "cache.db"),
        cache_dir=str(tmp_path / "cache_layer"),
    )
    app = create_app(config)

    with TestClient(app) as client:
        resp = client.get("/metrics")
        assert resp.status_code == 200


def test_findings_indexing_fallback_and_lookup(tmp_path: Path) -> None:
    # Set up simulated target and run directories with findings.json
    target_dir = tmp_path / "test_target"
    run_dir = target_dir / "run_abc"
    run_dir.mkdir(parents=True, exist_ok=True)

    findings_data = [
        {"id": "finding_1", "severity": "high", "title": "Test Finding 1"},
        {"id": "finding_2", "severity": "low", "title": "Test Finding 2"},
    ]
    (run_dir / "findings.json").write_text(json.dumps(findings_data), encoding="utf-8")

    # Perform indexed lookup
    res = _find_finding_by_id(tmp_path, "finding_2", tenant_id="default")
    assert res is not None
    assert res["id"] == "finding_2"

    # Verify findings_index.json was created
    index_file = tmp_path / "findings_index.json"
    assert index_file.exists()

    index_content = json.loads(index_file.read_text(encoding="utf-8"))
    assert "finding_1" in index_content
    assert index_content["finding_2"]["index"] == 2
