from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from src.dashboard.rate_limiter import RateLimitConfig, RateLimitMiddleware


def _build_app(config: RateLimitConfig) -> FastAPI:
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, config=config)

    @app.get("/api/jobs")
    async def jobs() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/api/jobs/{job_id}/logs")
    async def job_logs(job_id: str) -> dict[str, str]:
        return {"job_id": job_id}

    @app.get("/api/upstream-throttle")
    async def upstream_throttle() -> Response:
        return Response("slow down", status_code=429)

    @app.get("/api/waf")
    async def waf() -> Response:
        return Response("blocked", headers={"Server": "cloudflare"})

    @app.get("/assets/app.js")
    async def asset() -> Response:
        return Response("console.log('ok');", media_type="application/javascript")

    @app.get("/status")
    async def status() -> dict[str, bool]:
        return {"ok": True}

    return app


def test_rate_limiter_is_api_only_by_default() -> None:
    app = _build_app(
        RateLimitConfig(
            window_seconds=60.0,
            default_limit=1,
        )
    )
    client = TestClient(app)

    # Non-API route should not be rate-limited by the dashboard middleware.
    assert client.get("/status").status_code == 200
    assert client.get("/status").status_code == 200
    assert client.get("/status").status_code == 200

    # API route should still be limited.
    assert client.get("/api/jobs").status_code == 200
    assert client.get("/api/jobs").status_code == 429


def test_endpoint_prefix_limits_apply_to_nested_job_routes() -> None:
    app = _build_app(
        RateLimitConfig(
            window_seconds=60.0,
            default_limit=1,
            endpoint_prefix_limits={"/api/jobs/": 3},
        )
    )
    client = TestClient(app)

    assert client.get("/api/jobs/abc/logs").status_code == 200
    assert client.get("/api/jobs/abc/logs").status_code == 200
    assert client.get("/api/jobs/abc/logs").status_code == 200
    assert client.get("/api/jobs/abc/logs").status_code == 429


def test_exact_endpoint_limit_overrides_prefix_limit() -> None:
    app = _build_app(
        RateLimitConfig(
            window_seconds=60.0,
            default_limit=1,
            endpoint_prefix_limits={"/api/jobs/": 5},
            endpoint_limits={"/api/jobs/abc/logs": 2},
        )
    )
    client = TestClient(app)

    assert client.get("/api/jobs/abc/logs").status_code == 200
    assert client.get("/api/jobs/abc/logs").status_code == 200
    assert client.get("/api/jobs/abc/logs").status_code == 429


def test_excluded_prefix_bypasses_rate_limit_when_api_only_disabled() -> None:
    app = _build_app(
        RateLimitConfig(
            window_seconds=60.0,
            default_limit=1,
            api_only=False,
            excluded_prefixes={"/assets/"},
        )
    )
    client = TestClient(app)

    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/app.js").status_code == 200


def test_adaptive_limit_lowers_after_429_response() -> None:
    app = _build_app(
        RateLimitConfig(
            window_seconds=60.0,
            default_limit=4,
            adaptive_penalty_factor=0.5,
        )
    )
    client = TestClient(app)

    first = client.get("/api/upstream-throttle")
    assert first.status_code == 429
    assert first.headers["X-RateLimit-Adaptive"] == "1"
    assert first.headers["X-RateLimit-Limit"] == "2"

    assert client.get("/api/upstream-throttle").status_code == 429
    blocked = client.get("/api/upstream-throttle")
    assert blocked.status_code == 429
    assert blocked.json()["error"] == "Rate Limit Exceeded"
    assert blocked.headers["X-RateLimit-Limit"] == "1"


def test_adaptive_limit_detects_waf_headers() -> None:
    app = _build_app(
        RateLimitConfig(
            window_seconds=60.0,
            default_limit=4,
            adaptive_penalty_factor=0.5,
        )
    )
    client = TestClient(app)

    response = client.get("/api/waf")
    assert response.status_code == 200
    assert response.headers["X-RateLimit-Adaptive"] == "1"
    assert response.headers["X-RateLimit-Limit"] == "2"
