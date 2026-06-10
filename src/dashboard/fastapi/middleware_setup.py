"""Middleware registration for the FastAPI dashboard."""

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.middleware import (
    AuditLoggingMiddleware,
    CSRFProtectionMiddleware,
    RequestTimingMiddleware,
    SecurityHeadersMiddleware,
)
from src.dashboard.fastapi.response_validator import ResponseValidationMiddleware
from src.dashboard.fastapi.security import api_security_enabled
from src.dashboard.rate_limiter import RateLimitConfig, RateLimitMiddleware

logger = logging.getLogger(__name__)


def setup_middleware(app: FastAPI, config: DashboardConfig) -> None:
    origins = config.allowed_origins

    if not config.debug:
        _localhost_origins = [o for o in origins if "localhost" in o or "127.0.0.1" in o]
        if _localhost_origins:
            logger.warning(
                "CORS contains localhost origins in production mode: %s — "
                "these should be removed before deploying to a real environment.",
                _localhost_origins,
            )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            "Authorization",
            "X-API-Key",
            "X-Tenant-ID",
            "X-CSRF-Token",
        ],
    )

    security_enabled = api_security_enabled()
    rate_limit_config = RateLimitConfig(
        window_seconds=1.0 if security_enabled else 60.0,
        default_limit=int(os.getenv("RATE_LIMIT_GLOBAL_RPS", "30"))
        if security_enabled
        else config.rate_limit_default,
        jobs_limit=2 if security_enabled else config.rate_limit_jobs,
        replay_limit=config.rate_limit_replay,
        redis_url=config.redis_url,
        endpoint_limits={"/api/jobs": 2, "/api/jobs/start": 2} if security_enabled else {},
    )
    app.add_middleware(RateLimitMiddleware, config=rate_limit_config)
    app.add_middleware(CSRFProtectionMiddleware)
    app.add_middleware(RequestTimingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuditLoggingMiddleware)
    app.add_middleware(ResponseValidationMiddleware)
