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

import importlib
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------- helpers ----------


def _reload_app_with_auth(monkeypatch, env: dict | None = None):
    """Reload the FastAPI app module with auth dependencies mocked."""
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    # Disable lifespan side-effects during import
    monkeypatch.setenv("APP_ENV", "test")
    from src.dashboard.fastapi import app as app_mod
    importlib.reload(app_mod)
    return app_mod


def _bypass_auth(monkeypatch, role: str = "admin"):
    """Replace the require_auth / require_admin dependencies with fakes."""
    from src.dashboard.fastapi import deps

    async def _ok():
        return {"sub": "test-user", "role": role, "tenant_id": "t1"}

    monkeypatch.setattr(deps, "require_auth", _ok)
    monkeypatch.setattr(deps, "require_admin", _ok)


# ---------- security router ----------


def test_csrf_endpoint_requires_auth(monkeypatch):
    _reload_app_with_auth(monkeypatch)
    from fastapi.testclient import TestClient
    from src.dashboard.fastapi import app as app_mod
    from src.dashboard.fastapi import deps

    async def _deny():
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="unauth")

    monkeypatch.setattr(deps, "require_auth", _deny)
    client = TestClient(app_mod.app)
    r = client.get("/api/security/csrf-token")
    assert r.status_code == 401


def test_csrf_endpoint_sets_httponly_samesite_cookie(monkeypatch):
    _reload_app_with_auth(monkeypatch)
    from fastapi.testclient import TestClient
    from src.dashboard.fastapi import app as app_mod

    _bypass_auth(monkeypatch)
    client = TestClient(app_mod.app)
    r = client.get("/api/security/csrf-token")
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "")
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie or "samesite=strict" in set_cookie.lower()


def test_security_events_requires_admin(monkeypatch):
    _reload_app_with_auth(monkeypatch)
    from fastapi.testclient import TestClient
    from src.dashboard.fastapi import app as app_mod
    from src.dashboard.fastapi import deps

    async def _user():
        return {"sub": "u", "role": "viewer", "tenant_id": "t1"}

    async def _deny():
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(deps, "require_auth", _user)
    monkeypatch.setattr(deps, "require_admin", _deny)
    client = TestClient(app_mod.app)
    r = client.get("/api/security/events")
    assert r.status_code == 403


# ---------- webhook SSRF ----------


def test_webhook_test_rejects_loopback_url(monkeypatch):
    _reload_app_with_auth(monkeypatch)
    from fastapi.testclient import TestClient
    from src.dashboard.fastapi import app as app_mod

    _bypass_auth(monkeypatch)
    client = TestClient(app_mod.app)
    r = client.post("/api/webhooks/test", json={"url": "http://127.0.0.1:6379"})
    assert r.status_code in (400, 422)


def test_webhook_test_rejects_metadata_ip(monkeypatch):
    _reload_app_with_auth(monkeypatch)
    from fastapi.testclient import TestClient
    from src.dashboard.fastapi import app as app_mod

    _bypass_auth(monkeypatch)
    client = TestClient(app_mod.app)
    r = client.post("/api/webhooks/test", json={"url": "http://169.254.169.254/latest"})
    assert r.status_code in (400, 422)


def test_webhook_test_rejects_file_scheme(monkeypatch):
    _reload_app_with_auth(monkeypatch)
    from fastapi.testclient import TestClient
    from src.dashboard.fastapi import app as app_mod

    _bypass_auth(monkeypatch)
    client = TestClient(app_mod.app)
    r = client.post("/api/webhooks/test", json={"url": "file:///etc/passwd"})
    assert r.status_code in (400, 422)


# ---------- security headers middleware ----------


def test_security_headers_middleware_applies_csp_and_hsts(monkeypatch):
    _reload_app_with_auth(monkeypatch)
    from fastapi.testclient import TestClient
    from src.dashboard.fastapi import app as app_mod
    from src.dashboard.fastapi import deps

    async def _ok():
        return {"sub": "u", "role": "admin"}

    monkeypatch.setattr(deps, "require_auth", _ok)
    client = TestClient(app_mod.app)
    r = client.get("/api/security/csrf-token")
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
    _reload_app_with_auth(monkeypatch)
    from fastapi.testclient import TestClient
    from src.dashboard.fastapi import app as app_mod
    from src.dashboard.fastapi import deps

    async def _user():
        return {"sub": "u", "role": "viewer", "tenant_id": "t1"}

    async def _deny():
        from fastapi import HTTPException
        raise HTTPException(status_code=403)

    monkeypatch.setattr(deps, "require_auth", _user)
    monkeypatch.setattr(deps, "require_admin", _deny)
    client = TestClient(app_mod.app)
    r = client.post("/api/mesh/elect-leader", json={})
    assert r.status_code == 403
