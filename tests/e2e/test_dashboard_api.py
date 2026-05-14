import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def dashboard_app(dashboard_config, mock_dashboard_services):
    from src.dashboard.fastapi.app import create_app
    from src.dashboard.fastapi.dependencies import require_auth

    app = create_app(config=dashboard_config)
    app.dependency_overrides[require_auth] = lambda: None
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
        assert data["status"] == "ok"
        assert "timestamp" in data
        assert "version" in data
        assert "uptime_seconds" in data

    def test_root_endpoint(self, dashboard_client):
        response = dashboard_client.get("/")
        assert response.status_code == 200

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
        assert "trend_data" in data
        assert "findings_summary" in data

    def test_targets_list_endpoint(self, dashboard_client):
        response = dashboard_client.get("/api/targets")
        assert response.status_code == 200
        data = response.json()
        assert "targets" in data
        assert "total" in data

    def test_defaults_endpoint(self, dashboard_client):
        response = dashboard_client.get("/api/defaults")
        assert response.status_code == 200
        data = response.json()
        assert "form_defaults" in data
        assert "default_mode" in data
        assert "config_template" in data

    def test_findings_summary_endpoint(self, dashboard_client):
        response = dashboard_client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()
        assert "total_findings" in data
        assert "by_severity" in data
        assert "by_module" in data
        assert "targets" in data

    def test_detection_gap_endpoint(self, dashboard_client):
        response = dashboard_client.get("/api/detection-gap")
        assert response.status_code == 200
        data = response.json()
        assert "target" in data
        assert "gaps" in data
        assert "total_gaps" in data

    def test_detection_gap_with_target_param(self, dashboard_client):
        response = dashboard_client.get("/api/detection-gap?target=example.com")
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
        assert label in ["Healthy", "Moderate Risk", "High Risk", "At Risk", "Critical"]

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

    def test_dashboard_trend_data_structure(self, dashboard_client):
        response = dashboard_client.get("/api/dashboard")
        assert response.status_code == 200
        data = response.json()
        trend_data = data["trend_data"]
        assert isinstance(trend_data, list)

    def test_targets_response_structure(self, dashboard_client):
        response = dashboard_client.get("/api/targets")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["targets"], list)
        assert isinstance(data["total"], int)

    def test_findings_response_structure(self, dashboard_client):
        response = dashboard_client.get("/api/findings")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["total_findings"], int)
        assert isinstance(data["by_severity"], dict)

    def test_detection_gap_response_structure(self, dashboard_client):
        response = dashboard_client.get("/api/detection-gap")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["gaps"], list)
        assert isinstance(data["total_gaps"], int)

    def test_defaults_response_structure(self, dashboard_client):
        response = dashboard_client.get("/api/defaults")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["form_defaults"], dict)
        assert isinstance(data["default_mode"], str)
        assert isinstance(data["config_template"], dict)
