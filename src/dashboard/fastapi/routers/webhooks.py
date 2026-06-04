"""Webhook management and testing endpoints for the FastAPI dashboard."""

import logging
import threading
import time
from collections import deque
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.core.utils.url_validation import is_safe_url
from src.dashboard.fastapi.dependencies import require_auth
from src.dashboard.fastapi.validation import validate_url
from src.infrastructure.notifications.base import NotificationEvent, NotificationPriority
from src.infrastructure.notifications.manager import (
    ChannelEntry,
    ManagerConfig,
    NotificationManager,
)

router = APIRouter(prefix="/api/webhooks", tags=["Webhooks"])

logger = logging.getLogger(__name__)


class WebhookTestRequest(BaseModel):
    url: str = Field(..., description="The webhook URL to test")
    secret: str | None = Field(None, description="Optional HMAC signing secret")


# Bug #36 fix: per-tenant rate limit for outbound webhook tests. The
# endpoints accept arbitrary public URLs after SSRF validation, but
# without a frequency cap an authenticated user could otherwise turn
# the dashboard into a DNS-amplification / outbound-proxy primitive.
# We track the last ``_WEBHOOK_LIMIT_CALLS`` call timestamps per tenant
# and reject if more than ``_WEBHOOK_LIMIT_CALLS`` happened in the
# last ``_WEBHOOK_LIMIT_WINDOW_SECONDS`` seconds.
_WEBHOOK_LIMIT_CALLS = 5
_WEBHOOK_LIMIT_WINDOW_SECONDS = 60.0
_WEBHOOK_RATE_LOCK = threading.Lock()
_WEBHOOK_RATE_LOG: dict[str, deque[float]] = {}


def _enforce_webhook_rate_limit(tenant_id: str) -> None:
    """Raise 429 if ``tenant_id`` has exceeded the webhook test rate limit."""
    now = time.monotonic()
    with _WEBHOOK_RATE_LOCK:
        bucket = _WEBHOOK_RATE_LOG.setdefault(tenant_id or "default", deque())
        # Evict timestamps outside the window so the deque never grows
        # unbounded for a long-running process.
        while bucket and now - bucket[0] > _WEBHOOK_LIMIT_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= _WEBHOOK_LIMIT_CALLS:
            retry_after = max(1, int(_WEBHOOK_LIMIT_WINDOW_SECONDS - (now - bucket[0])))
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Webhook test rate limit exceeded ({_WEBHOOK_LIMIT_CALLS} "
                    f"calls per {_WEBHOOK_LIMIT_WINDOW_SECONDS:.0f}s). "
                    f"Retry after {retry_after}s."
                ),
                headers={"Retry-After": str(retry_after)},
            )
        bucket.append(now)


class SlackTestRequest(BaseModel):
    url: str = Field(..., description="The Slack Incoming Webhook URL")
    channel: str = Field("#security-alerts", description="The Slack channel to post to")


def _validate_webhook_url(url: str) -> None:
    """Reject URLs that point at private, loopback, link-local, or rebinding
    services. This closes the SSRF surface exposed by the test endpoints.
    """
    if not validate_url(url):
        raise HTTPException(status_code=400, detail="Invalid webhook URL format")
    if not is_safe_url(url):
        raise HTTPException(
            status_code=400,
            detail=(
                "Webhook URL points to a private, loopback, link-local, or "
                "rebinding-suspect address and was rejected."
            ),
        )


@router.post("/test")
async def test_webhook(
    payload: WebhookTestRequest,
    auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Test a custom HTTP webhook integration."""
    _enforce_webhook_rate_limit((auth or {}).get("tenant_id", "default"))
    _validate_webhook_url(payload.url)
    try:
        config = ManagerConfig(
            channels=[
                ChannelEntry(
                    name="webhook",
                    enabled=True,
                    config={
                        "url": payload.url,
                        "secret": payload.secret,
                    },
                )
            ]
        )

        async with NotificationManager(config) as manager:
            results = await manager.send(
                event=NotificationEvent.CUSTOM,
                priority=NotificationPriority.MEDIUM,
                title="Webhook Connectivity Test",
                message="This is a test message from the Cyber Security Test Pipeline to verify your webhook integration.",
                metadata={"test": True, "source": "dashboard_settings"},
            )

            if results and results[0].success:
                return {"status": "success", "message": "Test notification sent successfully"}

            error = results[0].error if results else "Unknown error"
            raise HTTPException(status_code=502, detail=f"Webhook test failed: {error}")

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to test webhook: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/test-slack")
async def test_slack(
    payload: SlackTestRequest,
    auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Test a Slack Incoming Webhook integration."""
    _enforce_webhook_rate_limit((auth or {}).get("tenant_id", "default"))
    _validate_webhook_url(payload.url)
    try:
        config = ManagerConfig(
            channels=[
                ChannelEntry(
                    name="slack",
                    enabled=True,
                    config={
                        "webhook_url": payload.url,
                        "channel": payload.channel,
                    },
                )
            ]
        )

        async with NotificationManager(config) as manager:
            results = await manager.send(
                event=NotificationEvent.CUSTOM,
                priority=NotificationPriority.MEDIUM,
                title="Slack Integration Test",
                message="🚀 *Cyber Security Test Pipeline*: This is a test message to verify your Slack incoming webhook configuration.",
                metadata={"test": True},
            )

            if results and results[0].success:
                return {"status": "success", "message": "Slack test message sent successfully"}

            error = results[0].error if results else "Unknown error"
            raise HTTPException(status_code=502, detail=f"Slack test failed: {error}")

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to test Slack: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
