"""Tests for CSRFProtectionMiddleware double-submit cookie CSRF protection."""

import secrets

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from src.dashboard.fastapi.middleware import CSRFProtectionMiddleware


def _create_app(auth_disabled: bool = False, app_env: str = "development"):
    """Create a test Starlette app with CSRF middleware."""

    async def test_endpoint(request: Request):
        return JSONResponse({"status": "ok"})

    async def csrf_token_endpoint(request: Request):
        token = secrets.token_urlsafe(32)
        return JSONResponse({"csrf_token": token})

    async def ws_endpoint(request: Request):
        return JSONResponse({"status": "ws"})

    async def auth_token_endpoint(request: Request):
        return JSONResponse({"status": "auth"})

    app = Starlette(routes=[
        Route("/api/test", endpoint=test_endpoint, methods=["GET", "POST", "PUT", "DELETE"]),
        Route("/api/csrf-token", endpoint=csrf_token_endpoint, methods=["GET"]),
        Route("/ws/test", endpoint=ws_endpoint, methods=["GET", "POST"]),
        Route("/api/auth/token", endpoint=auth_token_endpoint, methods=["POST"]),
    ])

    if auth_disabled:
        import os

        os.environ["DASHBOARD_AUTH_DISABLED"] = "1"
        os.environ["APP_ENV"] = app_env

    app.add_middleware(CSRFProtectionMiddleware)
    return app


class TestCSRFProtectionMiddleware:
    """Test suite for CSRFProtectionMiddleware."""

    def test_safe_methods_bypass_csrf(self):
        """GET, HEAD, OPTIONS should pass through without CSRF token."""
        app = _create_app()
        client = TestClient(app)
        response = client.get("/api/test")
        assert response.status_code == 200

    def test_post_without_csrf_token_rejected(self):
        """POST without CSRF token should return 403."""
        app = _create_app()
        client = TestClient(app)
        response = client.post("/api/test")
        assert response.status_code == 403
        assert "CSRF token missing" in response.json()["detail"]

    def test_post_with_csrf_token_accepted(self):
        """POST with matching CSRF cookie and header should pass."""
        app = _create_app()
        client = TestClient(app)
        token = secrets.token_urlsafe(32)
        response = client.post(
            "/api/test",
            cookies={"csrf_token": token},
            headers={"X-CSRF-Token": token},
        )
        assert response.status_code == 200

    def test_post_with_mismatched_csrf_token_rejected(self):
        """POST with mismatched CSRF token should return 403."""
        app = _create_app()
        client = TestClient(app)
        response = client.post(
            "/api/test",
            cookies={"csrf_token": "token-a"},
            headers={"X-CSRF-Token": "token-b"},
        )
        assert response.status_code == 403
        assert "CSRF token mismatch" in response.json()["detail"]

    def test_csrf_exempt_paths_bypass(self):
        """Exempt paths like /api/csrf-token and /api/auth/token bypass CSRF."""
        app = _create_app()
        client = TestClient(app)
        response = client.post("/api/auth/token")
        assert response.status_code == 200

    def test_websocket_paths_bypass_csrf(self):
        """WebSocket upgrade paths bypass CSRF."""
        app = _create_app()
        client = TestClient(app)
        response = client.post("/ws/test")
        assert response.status_code == 200

    def test_bearer_auth_exempts_csrf_without_session_cookie(self):
        """Bearer auth without session cookie should bypass CSRF."""
        app = _create_app()
        client = TestClient(app)
        response = client.post(
            "/api/test",
            headers={"Authorization": "Bearer test-token-123"},
        )
        assert response.status_code == 200

    def test_bearer_auth_with_session_cookie_requires_csrf(self):
        """Bearer auth WITH session cookie should still require CSRF."""
        app = _create_app()
        client = TestClient(app)
        response = client.post(
            "/api/test",
            cookies={"csrf_token": "session-cookie"},
            headers={"Authorization": "Bearer test-token-123"},
        )
        assert response.status_code == 403

    def test_api_key_auth_exempts_csrf_without_session_cookie(self):
        """API key auth without session cookie should bypass CSRF."""
        app = _create_app()
        client = TestClient(app)
        response = client.post(
            "/api/test",
            headers={"X-API-Key": "test-api-key"},
        )
        assert response.status_code == 200

    def test_auth_disabled_bypasses_csrf_in_dev(self):
        """CSRF should be disabled when DASHBOARD_AUTH_DISABLED=1 in non-production."""
        app = _create_app(auth_disabled=True, app_env="development")
        client = TestClient(app)
        response = client.post("/api/test")
        assert response.status_code == 200
        # Cleanup
        import os

        os.environ.pop("DASHBOARD_AUTH_DISABLED", None)

    def test_csrf_not_disabled_in_production(self):
        """CSRF should NOT be disabled even with DASHBOARD_AUTH_DISABLED=1 in production."""
        app = _create_app(auth_disabled=True, app_env="production")
        client = TestClient(app)
        response = client.post("/api/test")
        assert response.status_code == 403
        # Cleanup
        import os

        os.environ.pop("DASHBOARD_AUTH_DISABLED", None)
        os.environ["APP_ENV"] = "development"
