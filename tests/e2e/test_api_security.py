from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient


def _app(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ENABLE_API_SECURITY", "true")
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv("API_KEYS_JSON", '{"keys":[{"key":"admin-key","role":"admin"},{"key":"worker-key","role":"worker"},{"key":"read-key","role":"read_only"}]}')
    from src.dashboard.fastapi.app import create_app
    from src.dashboard.fastapi.config import DashboardConfig

    return create_app(
        DashboardConfig(
            output_root=tmp_path / "output",
            workspace_root=tmp_path,
            frontend_dist=tmp_path / "frontend_dist",
            config_template=tmp_path / "config_template.json",
            security_db_path=str(tmp_path / "security.db"),
            redis_url=None,
        )
    )


def test_token_endpoint_exchanges_api_key_for_jwt(tmp_path, monkeypatch):
    client = TestClient(_app(tmp_path, monkeypatch))

    response = client.post("/api/auth/token", json={"api_key": "admin-key"})

    assert response.status_code == 200
    data = response.json()
    assert data["access_token"]
    assert data["expires_in"] == 900
    assert data["role"] == "admin"


def test_security_api_key_management_requires_admin(tmp_path, monkeypatch):
    client = TestClient(_app(tmp_path, monkeypatch))
    token = client.post("/api/auth/token", json={"api_key": "admin-key"}).json()["access_token"]

    created = client.post(
        "/api/security/api-keys",
        json={"role": "worker"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert created.status_code == 200
    created_data = created.json()
    assert created_data["api_key"].startswith("cp_")
    assert created_data["masked_key"] != created_data["api_key"]

    listed = client.get("/api/security/api-keys", headers={"Authorization": f"Bearer {token}"})
    assert listed.status_code == 200
    assert any(item["id"] == created_data["id"] for item in listed.json())

    revoked = client.delete(
        f"/api/security/api-keys/{created_data['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert revoked.status_code == 200


def test_read_only_key_cannot_start_job(tmp_path, monkeypatch):
    client = TestClient(_app(tmp_path, monkeypatch))

    response = client.post(
        "/api/jobs",
        json={"base_url": "https://example.com"},
        headers={"X-API-Key": "read-key"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "403"


def test_unknown_json_fields_include_path_in_422(tmp_path, monkeypatch):
    monkeypatch.setenv("ENABLE_API_SECURITY", "false")
    from src.dashboard.fastapi.app import create_app
    from src.dashboard.fastapi.config import DashboardConfig

    app = create_app(
        DashboardConfig(
            output_root=tmp_path / "output",
            workspace_root=tmp_path,
            frontend_dist=tmp_path / "frontend_dist",
            config_template=tmp_path / "config_template.json",
            security_db_path=str(tmp_path / "security.db"),
            redis_url=None,
        )
    )
    app.state.services = MagicMock()
    client = TestClient(app)

    response = client.post(
        "/api/jobs/start",
        json={"base_url": "https://example.com", "unexpected": True},
    )

    assert response.status_code == 422
    unknown = response.json()["detail"][0]
    assert unknown["type"] == "extra_forbidden"
    assert unknown["path"] == "body.unexpected"


def test_csp_report_is_logged(tmp_path, monkeypatch):
    client = TestClient(_app(tmp_path, monkeypatch))
    token = client.post("/api/auth/token", json={"api_key": "read-key"}).json()["access_token"]

    report = {"csp-report": {"blocked-uri": "https://evil.example/script.js"}}
    accepted = client.post("/api/csp-report", json=report)
    assert accepted.status_code == 204

    reports = client.get(
        "/api/security/csp-reports",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert reports.status_code == 200
    assert reports.json()[0]["report"] == report
