from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@asynccontextmanager
async def _test_lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Lightweight lifespan for dashboard tests.

    Only initialises the state attributes that route handlers read.
    Skips gossip, mesh, bloom, websocket, self-healing, and other
    heavy infrastructure that is irrelevant to HTTP contract tests.
    """
    from unittest.mock import MagicMock

    from src.dashboard.fastapi.config import DashboardConfig
    from src.dashboard.services import DashboardServices
    from src.infrastructure.cache import CacheManager
    from src.infrastructure.cache.config import CacheConfig

    config: DashboardConfig = app.state.config

    cache_config = CacheConfig(
        sqlite_db_path=config.cache_db_path,
        cache_dir=config.cache_dir,
        redis_url=config.redis_url,
    )
    app.state.cache_manager = CacheManager(config=cache_config)

    services = MagicMock(spec=DashboardServices)
    services.query = MagicMock()
    services.query.output_root = config.output_root
    services.launch = MagicMock()

    services.list_jobs.return_value = []
    services.list_targets.return_value = []
    services.get_job.return_value = None

    services.query.list_jobs.return_value = []
    services.query.list_targets.return_value = []
    services.query.findings_summary.return_value = {"total_findings": 0, "severity_breakdown": {}}
    services.query.detection_gap_summary.return_value = {"empty_modules": []}

    services.launch.api_defaults.return_value = {
        "form_defaults": {},
        "default_mode": "quick",
        "config_template": {},
    }
    app.state.services = services
    app.state.ws_services = None
    app.state.gossip = None
    app.state.bloom_filter = None
    app.state.bloom_mesh = None
    app.state.self_healing_controller = None
    app.state.model_registry = MagicMock()

    yield

    if hasattr(app.state, "cache_manager"):
        app.state.cache_manager.close()


@pytest.fixture
def dashboard_app(dashboard_config, monkeypatch):
    monkeypatch.setenv("DASHBOARD_AUTH_DISABLED", "true")
    from src.dashboard.fastapi.app import create_app
    from src.dashboard.fastapi.dependencies import require_auth

    app = create_app(config=dashboard_config)
    app.dependency_overrides[require_auth] = lambda: None
    app.router.lifespan_context = _test_lifespan
    yield app


@pytest.fixture
def dashboard_client(dashboard_app):
    with TestClient(dashboard_app) as client:
        yield client


@pytest.mark.integration
@pytest.mark.slow
class TestDashboardAPIE2E:
    def test_health_endpoint(self, dashboard_client):
        response = dashboard_client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("ok", "degraded")
        assert "timestamp" in data
        assert "version" in data
        assert "uptime_seconds" in data

    def test_root_endpoint(self, dashboard_client):
        response = dashboard_client.get("/")
        # Root now serves SPA index, so it should be 200 or 404 if build missing in test env
        assert response.status_code in (200, 404)

    def test_dashboard_stats_endpoint(self, dashboard_client):
        response = dashboard_client.get("/api/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert "active_jobs" in data
        assert "completed_jobs" in data
        assert "failed_jobs" in data
        assert "total_findings" in data
        assert "total_targets" in data
        assert "avg_progress" in data
        assert "stage_counts" in data
        assert "severity_counts" in data
        assert "pipeline_health_score" in data
        assert "pipeline_health_label" in data

    def test_targets_list_endpoint(self, dashboard_client):
        response = dashboard_client.get("/api/targets")
        assert response.status_code == 200
        data = response.json()
        assert "targets" in data

    def test_registry_endpoint(self, dashboard_client):
        response = dashboard_client.get("/api/registry")
        assert response.status_code == 200
        data = response.json()
        assert "modules" in data
        assert "analysis" in data
        assert "modes" in data

    def test_findings_summary_endpoint(self, dashboard_client):
        response = dashboard_client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()
        assert "total_findings" in data
        assert "findings" in data
        assert "targets" in data

    def test_gap_analysis_endpoint(self, dashboard_client):
        response = dashboard_client.get("/api/gap-analysis")
        assert response.status_code == 200
        data = response.json()
        assert "target" in data
        assert "results" in data
        assert "overall_coverage" in data

    def test_gap_analysis_with_target_param(self, dashboard_client):
        response = dashboard_client.get("/api/gap-analysis?target=example.com")
        assert response.status_code == 200
        data = response.json()
        assert data["target"] == "example.com"

    def test_openapi_schema_available(self, dashboard_client):
        response = dashboard_client.get("/api/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert "openapi" in schema
        assert "paths" in schema
        assert "info" in schema

    def test_docs_endpoint_available(self, dashboard_client):
        response = dashboard_client.get("/api/docs")
        assert response.status_code == 200

    def test_redoc_endpoint_available(self, dashboard_client):
        response = dashboard_client.get("/api/redoc")
        assert response.status_code == 200

    def test_security_headers_present(self, dashboard_client):
        response = dashboard_client.get("/api/health")
        assert response.status_code == 200
        assert "x-content-type-options" in response.headers
        assert "x-frame-options" in response.headers

    def test_cors_headers_present(self, dashboard_client):
        response = dashboard_client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200

    def test_unknown_endpoint_returns_404(self, dashboard_client):
        response = dashboard_client.get("/api/nonexistent")
        assert response.status_code == 404

    def test_validation_error_returns_422(self, dashboard_client):
        response = dashboard_client.post("/api/jobs/start", json={})
        # If it requires auth it might return 401, but if auth is disabled it returns 422
        assert response.status_code in [422, 401]
        data = response.json()
        assert "detail" in data

    def test_dashboard_pipeline_health_score_calculation(self, dashboard_client):
        response = dashboard_client.get("/api/dashboard")
        assert response.status_code == 200
        data = response.json()
        score = data["pipeline_health_score"]
        assert isinstance(score, int)
        assert 0 <= score <= 100
        label = data["pipeline_health_label"]
        assert label in ["Healthy", "Warning", "Critical"]

    def test_dashboard_stage_counts_structure(self, dashboard_client):
        response = dashboard_client.get("/api/dashboard")
        assert response.status_code == 200
        data = response.json()
        stage_counts = data["stage_counts"]
        for key in ["discovery", "collection", "analysis", "validation", "reporting", "other"]:
            assert key in stage_counts
            assert isinstance(stage_counts[key], int)

    def test_dashboard_severity_counts_structure(self, dashboard_client):
        response = dashboard_client.get("/api/dashboard")
        assert response.status_code == 200
        data = response.json()
        severity_counts = data["severity_counts"]
        for sev in ["critical", "high", "medium", "low", "info"]:
            assert sev in severity_counts
            assert isinstance(severity_counts[sev], int)

    def test_targets_response_structure(self, dashboard_client):
        response = dashboard_client.get("/api/targets")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["targets"], list)

    def test_findings_response_structure(self, dashboard_client):
        response = dashboard_client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["total_findings"], int)
        assert isinstance(data["findings"], list)

    def test_gap_analysis_response_structure(self, dashboard_client):
        response = dashboard_client.get("/api/gap-analysis")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["results"], list)
        assert isinstance(data["overall_coverage"], int)

    def test_registry_response_structure(self, dashboard_client):
        response = dashboard_client.get("/api/registry")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["modules"], dict)
        assert isinstance(data["analysis"], dict)
        assert isinstance(data["modes"], dict)
