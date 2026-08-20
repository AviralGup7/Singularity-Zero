"""
Security boundary tests — close the externally reachable holes.

Acceptance scenarios:

  unauthenticated → report               = 401
  tenant A → tenant B report             = denied (404)
  tenant A → tenant B SSE                = denied (404)
  default tenant → arbitrary job         = denied
  production + auth disabled             = startup failure
  private target                         = blocked by default

Also verifies:
  * hidden report/launcher routes require auth (S-1)
  * WS job-ownership checker is wired and fail-closed (S-3d)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.core.security.secret_validator import (
    enforce_production_security,
    find_production_security_violations,
)
from src.core.utils.url_validation import is_safe_url
from src.dashboard.fastapi.dependencies import require_auth, set_app_ref
from src.dashboard.fastapi.routers.launcher import router as launcher_router
from src.dashboard.fastapi.routers.targets import is_target_owned_by_tenant
from src.dashboard.fastapi.routers.utils import job_target_name

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


class _FakeServices:
    """Minimal queue-services stand-in with a job store."""

    def __init__(self, jobs: dict[str, dict[str, Any]]):
        self.jobs = jobs

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        return self.jobs.get(job_id)


class _FakeConfig:
    def __init__(self, output_root: Path):
        self.output_root = output_root
        self.api_key = None
        self.admin_keys = []
        self.debug = False


def _build_app(tmp_path: Path, jobs: dict[str, dict[str, Any]] | None = None) -> FastAPI:
    """Minimal app with the launcher router wired and a fake services store."""
    app = FastAPI()
    app.state.config = _FakeConfig(tmp_path)
    app.state.services = _FakeServices(jobs or {})
    set_app_ref(app)
    app.include_router(launcher_router)
    return app


def _make_report(output_root: Path, target: str, filename: str = "report.html") -> Path:
    """Create a report file on disk so the route can serve it."""
    path = output_root / target / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("<html>report</html>", encoding="utf-8")
    return path


# ===================================================================
# S-1 — unauthenticated → report = 401
# ===================================================================


def test_unauthenticated_report_returns_401(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("DASHBOARD_AUTH_DISABLED", raising=False)
    _make_report(tmp_path, "example.com")
    app = _build_app(tmp_path)
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/reports/example.com/report.html")
    assert resp.status_code == 401, f"unauthenticated report should be 401, got {resp.status_code}"


def test_unauthenticated_launcher_returns_401(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("DASHBOARD_AUTH_DISABLED", raising=False)
    app = _build_app(tmp_path)
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/launcher/some-job/stdout.txt")
    assert resp.status_code == 401, (
        f"unauthenticated launcher should be 401, got {resp.status_code}"
    )


# ===================================================================
# S-1/S-4 — tenant A → tenant B report = denied
# ===================================================================


def test_tenant_a_cannot_read_tenant_b_report(tmp_path: Path):
    _make_report(tmp_path, "tenantB_example.com")
    _make_report(tmp_path, "tenantA_example.com")
    app = _build_app(tmp_path)
    app.dependency_overrides[require_auth] = lambda: {
        "user": "alice",
        "role": "viewer",
        "tenant_id": "tenantA",
        "auth_method": "jwt",
    }
    client = TestClient(app, raise_server_exceptions=False)

    # Cross-tenant target → denied
    resp = client.get("/reports/tenantB_example.com/report.html")
    assert resp.status_code == 404, (
        f"tenantA reading tenantB report should be 404, got {resp.status_code}"
    )

    # Own tenant target → served
    resp_ok = client.get("/reports/tenantA_example.com/report.html")
    assert resp_ok.status_code == 200, (
        f"tenantA reading own report should be 200, got {resp_ok.status_code}"
    )


def test_tenant_a_cannot_read_tenant_b_launcher_artifact(tmp_path: Path):
    jobs = {
        "job-b": {"id": "job-b", "target_name": "tenantB_example.com", "status": "running"},
    }
    app = _build_app(tmp_path, jobs=jobs)
    app.dependency_overrides[require_auth] = lambda: {
        "user": "alice",
        "role": "viewer",
        "tenant_id": "tenantA",
        "auth_method": "jwt",
    }
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/launcher/job-b/stdout.txt")
    assert resp.status_code == 404, (
        f"tenantA reading tenantB job artifact should be 404, got {resp.status_code}"
    )


# ===================================================================
# S-4 — default tenant cannot access another tenant's job
# ===================================================================


def test_default_tenant_cannot_access_tenant_b_job():
    # The SSE path and report path both funnel through
    # is_target_owned_by_tenant(job_target_name(job), tenant_id).
    job = {"id": "job-b", "target_name": "tenantB_example.com", "status": "running"}
    target = job_target_name(job)
    assert target == "tenantB_example.com"
    assert is_target_owned_by_tenant(target, "default") is False, (
        "default tenant must not own tenantB-prefixed targets"
    )
    assert is_target_owned_by_tenant(target, "tenantB") is True, "tenantB must own its own targets"


def test_tenant_a_cannot_access_tenant_b_job():
    job = {"id": "job-b", "target": "tenantB_example.com"}
    target = job_target_name(job)
    assert is_target_owned_by_tenant(target, "tenantA") is False
    assert is_target_owned_by_tenant(target, "tenantB") is True


# ===================================================================
# S-3d — tenant A → tenant B SSE = denied
# ===================================================================


def test_tenant_a_sse_stream_denied(tmp_path: Path):
    """The SSE stream endpoint verifies job → target → tenant ownership.

    We exercise the exact decision function the route uses:
    ``is_target_owned_by_tenant(job_target_name(job), tenant_id)`` — a
    mismatched tenant yields the same 404 the route raises.
    """
    jobs = {
        "job-b": {"id": "job-b", "target_name": "tenantB_example.com", "status": "running"},
    }
    _build_app(tmp_path, jobs=jobs)
    tenant_a = {"tenant_id": "tenantA"}

    # The route's logic (mirrors sse_streaming.py):
    from src.dashboard.fastapi.routers.jobs import sse_streaming  # noqa: F401

    job = jobs["job-b"]
    target = job_target_name(job)
    tenant_id = tenant_a["tenant_id"]
    owned = is_target_owned_by_tenant(target, tenant_id)
    assert owned is False, "tenantA must be denied the tenantB job stream"

    # A matching tenant is allowed
    assert is_target_owned_by_tenant(target, "tenantB") is True


# ===================================================================
# S-10 — production + auth disabled = startup failure
# ===================================================================


def test_production_auth_disabled_fails_startup():
    with pytest.raises(RuntimeError, match="DASHBOARD_AUTH_DISABLED"):
        enforce_production_security(
            {
                "APP_ENV": "production",
                "DASHBOARD_AUTH_DISABLED": "true",
                "DASHBOARD_HOST": "127.0.0.1",
            }
        )


def test_production_auth_disabled_wildcard_bind_fails():
    violations = find_production_security_violations(
        {
            "APP_ENV": "production",
            "DASHBOARD_AUTH_DISABLED": "1",
            "DASHBOARD_HOST": "0.0.0.0",
        }
    )
    assert any("DASHBOARD_AUTH_DISABLED" in v for v in violations)
    assert any("0.0.0.0" in v for v in violations), "wildcard bind + auth disabled must be flagged"


def test_production_auth_enabled_allows_startup():
    # Auth enabled + loopback bind → no violations
    violations = find_production_security_violations(
        {
            "APP_ENV": "production",
            "DASHBOARD_AUTH_DISABLED": "false",
            "APP_SECRET_KEY": "s" * 48,
            "DASHBOARD_HOST": "127.0.0.1",
        }
    )
    # APP_SECRET_KEY of 48 chars passes the placeholder check
    assert not any("DASHBOARD_AUTH_DISABLED" in v for v in violations)


# ===================================================================
# Private-target policy — deny by default
# ===================================================================


def test_private_targets_blocked_by_default():
    assert is_safe_url("http://127.0.0.1/") is False, "loopback must be blocked"
    assert is_safe_url("http://localhost/") is False, "localhost must be blocked"
    assert is_safe_url("http://10.0.0.1/") is False, "RFC1918 must be blocked"
    assert is_safe_url("http://192.168.1.1/") is False, "RFC1918 must be blocked"
    assert is_safe_url("http://169.254.169.254/latest/meta-data/") is False, (
        "cloud metadata must be blocked"
    )
    assert is_safe_url("http://[::1]/") is False, "IPv6 loopback must be blocked"
    assert is_safe_url("http://0.0.0.0/") is False, "wildcard must be blocked"


def test_replay_private_targets_blocked():
    from src.dashboard.fastapi.validation import is_safe_replay_url

    assert is_safe_replay_url("http://127.0.0.1/x") is False
    assert is_safe_replay_url("http://169.254.169.254/") is False
    assert is_safe_replay_url("http://10.1.2.3/") is False
    assert is_safe_replay_url("http://metadata.local/") is False, (
        "special-use suffix must be blocked"
    )


# ===================================================================
# S-3d — WS job-ownership checker is wired and fail-closed
# ===================================================================


def test_ws_ownership_checker_fail_closed_without_services(tmp_path: Path):
    """Without a services store, the default WS checker denies the job."""
    from src.websocket_server.integration import get_ws_services, setup_websocket_routes

    app = FastAPI()
    # No services on state → checker must fail closed
    app.state.ws_enforce_job_ownership = True
    setup_websocket_routes(app)

    handler = get_ws_services().handler
    checker = handler.job_ownership_checker
    assert checker is not None, "job ownership checker must be wired by default"
    assert checker("anyuser", "job-1") is False, (
        "WS ownership check must fail closed when services are unavailable"
    )


def test_ws_ownership_checker_denies_cross_tenant(tmp_path: Path):
    from src.websocket_server.integration import get_ws_services, setup_websocket_routes

    jobs = {
        "job-b": {"id": "job-b", "target_name": "tenantB_example.com", "status": "running"},
    }
    services = _FakeServices(jobs)

    app = FastAPI()
    app.state.services = services
    app.state.ws_enforce_job_ownership = True
    setup_websocket_routes(app)

    handler = get_ws_services().handler
    checker = handler.job_ownership_checker
    assert checker is not None

    # tenantA caller (user_id "tenantA/alice") cannot subscribe to tenantB job
    assert checker("tenantA/alice", "job-b") is False, "cross-tenant WS subscription must be denied"
    # tenantB caller can
    assert checker("tenantB/bob", "job-b") is True, "same-tenant WS subscription must be allowed"
