"""Security monitoring and API key management endpoints."""

from __future__ import annotations

import os
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

from src.dashboard.fastapi.dependencies import get_config, require_admin, require_auth

# Maximum body size for CSP violation reports (256 KiB).
_MAX_CSP_REPORT_BYTES: int = 256 * 1024
from src.dashboard.fastapi.schemas import (
    APIKeyCreateRequest,
    APIKeyCreateResponse,
    APIKeyResponse,
    CSPReportResponse,
    ErrorResponse,
    RateLimitStatusResponse,
    SecurityEventResponse,
    TokenRequest,
    TokenResponse,
)
from src.dashboard.fastapi.security import api_security_enabled, create_jwt, Principal
from src.dashboard.rate_limiter import get_rate_limit_status

router = APIRouter(tags=["Security"])

_CSRF_COOKIE_NAME = "csrf_token"


@router.get(
    "/api/csrf-token",
    summary="Retrieve the current active CSRF token for the session",
    responses={401: {"model": ErrorResponse}},
)
async def get_csrf_token(
    request: Request,
    _auth: Any = Depends(require_auth),
) -> Response:
    """Issue a fresh CSRF token, set it as an HttpOnly cookie, and return it.

    The endpoint now requires authentication. The cookie is ``HttpOnly``,
    ``Secure`` (in production) and ``SameSite=Strict`` so it cannot be
    exfiltrated by client-side scripts. The response body returns the
    token so SPAs can copy it into the ``X-CSRF-Token`` header.
    """
    import secrets

    csrf_token = request.cookies.get(_CSRF_COOKIE_NAME) or secrets.token_urlsafe(32)
    response = JSONResponse(content={"csrf_token": csrf_token})
    response.set_cookie(
        key=_CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=60 * 60 * 8,
        httponly=True,
        secure=(os.environ.get("APP_ENV") == "production"),
        samesite="strict",
        path="/",
    )
    return response


@router.post(
    "/api/auth/token",
    response_model=TokenResponse,
    responses={401: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    summary="Exchange an API key for a short-lived dashboard token",
)
async def create_dashboard_token(
    request: Request,
    body: TokenRequest,
) -> TokenResponse:
    store = request.app.state.security_store
    config: DashboardConfig = getattr(request.app.state, "config", get_config())
    principal: Principal | None = None
    if body.mode and body.mode.lower() == "guest":
        guest_enabled = bool(getattr(config, "guest_access_enabled", False)) and api_security_enabled()
        if not guest_enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Guest authentication is disabled for this deployment",
            )
        principal = Principal(user="guest", role="guest", tenant_id="default", auth_method="guest")
    elif body.api_key:
        principal = store.authenticate_key(body.api_key)
    if principal is None:
        store.record_event(
            "invalid_auth",
            status_code=401,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else "unknown",
            detail="Invalid API key token exchange",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    store.record_event(
        "guest_auth",
        status_code=200,
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else "unknown",
        detail={"auth_method": "guest", "token_role": "guest"},
    )
    return TokenResponse(**create_jwt(principal))


@router.get(
    "/api/security/rate-limit-status",
    response_model=RateLimitStatusResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Get current rate limiting telemetry",
)
async def rate_limit_status(_admin: Any = Depends(require_admin)) -> RateLimitStatusResponse:
    return RateLimitStatusResponse(
        enabled=api_security_enabled(),
        buckets=cast(Any, get_rate_limit_status()),
    )


@router.get(
    "/api/security/events",
    response_model=list[SecurityEventResponse],
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="List recent security events",
)
async def list_security_events(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    _admin: Any = Depends(require_admin),
) -> list[SecurityEventResponse]:
    return [
        SecurityEventResponse(**event)
        for event in request.app.state.security_store.list_events(limit)
    ]


@router.get(
    "/api/security/api-keys",
    response_model=list[APIKeyResponse],
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="List API keys",
)
async def list_api_keys(
    request: Request,
    _admin: Any = Depends(require_admin),
) -> list[APIKeyResponse]:
    return [APIKeyResponse(**key) for key in request.app.state.security_store.list_keys()]


@router.post(
    "/api/security/api-keys",
    response_model=APIKeyCreateResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="Generate an API key",
)
async def generate_api_key(
    request: Request,
    body: APIKeyCreateRequest,
    auth: Any = Depends(require_admin),
) -> APIKeyCreateResponse:
    record = request.app.state.security_store.generate_key(body.role)
    request.app.state.security_store.record_event(
        "api_key_generated",
        status_code=201,
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else "unknown",
        api_key_id=auth.get("api_key_id"),
        detail={"role": body.role, "generated_key_id": record["id"]},
    )
    return APIKeyCreateResponse(**record)


@router.delete(
    "/api/security/api-keys/{key_id}",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Revoke an API key",
)
async def revoke_api_key(
    key_id: str,
    request: Request,
    auth: Any = Depends(require_admin),
) -> dict[str, bool | str]:
    revoked = request.app.state.security_store.revoke_key(key_id)
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    request.app.state.security_store.record_event(
        "api_key_revoked",
        status_code=200,
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else "unknown",
        api_key_id=auth.get("api_key_id"),
        detail={"revoked_key_id": key_id},
    )
    return {"revoked": True, "id": key_id}


@router.get(
    "/api/security/csp-reports",
    response_model=list[CSPReportResponse],
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="List CSP violation reports",
)
async def list_csp_reports(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    _admin: Any = Depends(require_admin),
) -> list[CSPReportResponse]:
    return [
        CSPReportResponse(**report)
        for report in request.app.state.security_store.list_csp_reports(limit)
    ]


@router.post(
    "/api/csp-report",
    status_code=204,
    summary="Accept a CSP violation report",
)
async def csp_report(request: Request) -> Response:
    body = await request.body()
    if len(body) > _MAX_CSP_REPORT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="CSP report body exceeds size limit",
        )
    import json

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid CSP report"
        )
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid CSP report"
        )
    request.app.state.security_store.record_csp_report(request, payload)
    return Response(status_code=204)
