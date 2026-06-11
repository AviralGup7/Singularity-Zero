"""Tests for guest authentication flow exposed by the security router."""

from __future__ import annotations

from unittest.mock import MagicMock

from fastapi.testclient import TestClient


def _app(tmp_path, monkeypatch, guest_access_enabled: bool, enable_api_security: str = "true"):
    monkeypatch.setenv("ENABLE_API_SECURITY", enable_api_security)
    monkeypatch.setenv("APP_SECRET_KEY", "test-secret")
    monkeypatch.setenv(
        "API_KEYS_JSON",
        '{"keys":[{"key":"admin-key","role":"admin"}]}',
    )
    from src.dashboard.fastapi.app import create_app as create
    from src.dashboard.fastapi.config import DashboardConfig as DC  # noqa: N817

    return create(
        DC(
            output_root=tmp_path / "output",
            workspace_root=tmp_path,
            frontend_dist=tmp_path / "frontend_dist",
            config_template=tmp_path / "config_template.json",
            security_db_path=str(tmp_path / "security.db"),
            redis_url=None,
            guest_access_enabled=guest_access_enabled,
        )
    )


def test_guest_token_when_guest_enabled_and_security_on(tmp_path, monkeypatch):
    guest_app = _app(tmp_path, monkeypatch, guest_access_enabled=True)
    guest_app.state.services = MagicMock()
    client = TestClient(guest_app)

    response = client.post("/api/auth/token", json={"mode": "guest"})
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"]
    assert data["role"] == "guest"
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 900


def test_guest_token_rejected_when_guest_disabled(tmp_path, monkeypatch):
    guest_app = _app(tmp_path, monkeypatch, guest_access_enabled=False)
    guest_app.state.services = MagicMock()
    client = TestClient(guest_app)

    response = client.post("/api/auth/token", json={"mode": "guest"})
    assert response.status_code == 403


def test_guest_token_rejected_when_security_disabled(tmp_path, monkeypatch):
    guest_app = _app(tmp_path, monkeypatch, guest_access_enabled=True, enable_api_security="false")
    guest_app.state.services = MagicMock()
    client = TestClient(guest_app)

    response = client.post("/api/auth/token", json={"mode": "guest"})
    assert response.status_code == 403


def test_api_key_token_still_works(tmp_path, monkeypatch):
    guest_app = _app(tmp_path, monkeypatch, guest_access_enabled=True)
    guest_app.state.services = MagicMock()
    client = TestClient(guest_app)

    response = client.post("/api/auth/token", json={"api_key": "admin-key"})
    assert response.status_code == 200
    assert response.json()["role"] == "admin"
