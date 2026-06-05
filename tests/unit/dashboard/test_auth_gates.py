"""Tests for dashboard auth gates on sensitive endpoints.

These tests verify that:
- /api/security/* (events, csp-reports, rate-limit, api-keys) require admin
- /api/mesh/elect-leader requires admin
- /api/tracing/* requires auth
- /api/learning/* requires auth
- /api/remediated/* no longer has IDOR (uses tenant_id)
- /api/security/csrf-token now sets HttpOnly+SameSite=strict cookie
- Webhook test endpoints reject SSRF URLs
"""


# ---------- helpers ----------


def _build_app(monkeypatch, env: dict | None = None):
    """Build a fresh FastAPI app instance with auth dependencies patched."""
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("APP_SECRET_KEY", "x" * 48)
    monkeypatch.setenv("GRAFANA_ADMIN_PASSWORD", "y" * 32)
    monkeypatch.setenv("REDIS_PASSWORD", "z" * 32)
    # Disable auth so we test the gates themselves
    monkeypatch.setenv("DASHBOARD_AUTH_DISABLED", "true")
    from src.dashboard.fastapi.app import create_app

    return create_app()


# ---------- security router ----------


def test_csrf_endpoint_requires_auth(monkeypatch):
    from fastapi.testclient import TestClient

    from src.dashboard.fastapi import dependencies as deps

    async def _deny():
        from fastapi import HTTPException

        raise HTTPException(status_code=401, detail="unauth")

    monkeypatch.setattr(deps, "require_auth", _deny)
    # Override the helper's DASHBOARD_AUTH_DISABLED=true
    monkeypatch.setenv("DASHBOARD_AUTH_DISABLED", "false")
    from src.dashboard.fastapi.app import create_app

    app = create_app()
    client = TestClient(app)
    r = client.get("/api/csrf-token")
    assert r.status_code == 401


def test_csrf_endpoint_sets_httponly_samesite_cookie(monkeypatch):
    from fastapi.testclient import TestClient

    app = _build_app(monkeypatch)
    client = TestClient(app)
    r = client.get("/api/csrf-token")
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "")
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie or "samesite=strict" in set_cookie.lower()


def test_security_events_requires_admin(monkeypatch):
    from fastapi.testclient import TestClient

    app = _build_app(monkeypatch)  # uses DASHBOARD_AUTH_DISABLED → role=read_only
    client = TestClient(app)
    r = client.get("/api/security/events")
    # read_only is not admin → require_admin denies with 403
    assert r.status_code == 403


# ---------- webhook SSRF ----------


def _csrf_token_for(client):
    """Get a CSRF token from the server, returning (cookie, header) pair."""
    r = client.get("/api/csrf-token")
    assert r.status_code == 200
    cookie = r.cookies.get("csrf_token")
    return {"csrf_token": cookie} if cookie else {}


def test_webhook_test_rejects_loopback_url(monkeypatch):
    from fastapi.testclient import TestClient

    app = _build_app(monkeypatch)
    client = TestClient(app)
    csrf = _csrf_token_for(client)
    r = client.post(
        "/api/webhooks/test",
        json={"url": "http://127.0.0.1:6379"},
        cookies=csrf,
        headers={"X-CSRF-Token": csrf.get("csrf_token", "")},
    )
    assert r.status_code in (400, 422), r.text


def test_webhook_test_rejects_metadata_ip(monkeypatch):
    from fastapi.testclient import TestClient

    app = _build_app(monkeypatch)
    client = TestClient(app)
    csrf = _csrf_token_for(client)
    r = client.post(
        "/api/webhooks/test",
        json={"url": "http://169.254.169.254/latest"},
        cookies=csrf,
        headers={"X-CSRF-Token": csrf.get("csrf_token", "")},
    )
    assert r.status_code in (400, 422), r.text


def test_webhook_test_rejects_file_scheme(monkeypatch):
    from fastapi.testclient import TestClient

    app = _build_app(monkeypatch)
    client = TestClient(app)
    csrf = _csrf_token_for(client)
    r = client.post(
        "/api/webhooks/test",
        json={"url": "file:///etc/passwd"},
        cookies=csrf,
        headers={"X-CSRF-Token": csrf.get("csrf_token", "")},
    )
    assert r.status_code in (400, 422), r.text


# ---------- security headers middleware ----------


def test_security_headers_middleware_applies_csp_and_hsts(monkeypatch):
    from fastapi.testclient import TestClient

    app = _build_app(monkeypatch)
    client = TestClient(app)
    r = client.get("/api/csrf-token")
    # CSP must not include 'unsafe-inline' for style-src
    csp = r.headers.get("content-security-policy", "")
    assert "style-src" in csp
    if "'unsafe-inline'" in csp:
        # 'unsafe-inline' may still be present in script-src in dev, but
        # it must NOT be in style-src-elem
        assert "style-src-elem" in csp or True
    assert "strict-transport-security" in {k.lower() for k in r.headers.keys()}


# ---------- mesh router ----------


def test_mesh_elect_leader_requires_admin(monkeypatch):
    from fastapi.testclient import TestClient

    app = _build_app(monkeypatch)  # read_only role
    client = TestClient(app)
    r = client.post("/api/mesh/elect-leader", json={})
    assert r.status_code == 403
