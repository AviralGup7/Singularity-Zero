"""Webhook management and testing endpoints for the FastAPI dashboard."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from src.dashboard.fastapi.dependencies import require_auth
from src.infrastructure.notifications.base import NotificationEvent, NotificationPriority
from src.infrastructure.notifications.manager import ManagerConfig, NotificationManager

router = APIRouter(prefix="/api/webhooks", tags=["Webhooks"])

logger = logging.getLogger(__name__)


class WebhookTestRequest(BaseModel):
    url: str = Field(..., description="The webhook URL to test")
    secret: str | None = Field(None, description="Optional HMAC signing secret")


class SlackTestRequest(BaseModel):
    url: str = Field(..., description="The Slack Incoming Webhook URL")
    channel: str = Field("#security-alerts", description="The Slack channel to post to")


@router.post("/test")
async def test_webhook(
    payload: WebhookTestRequest,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Test a custom HTTP webhook integration."""
    try:
        config = ManagerConfig(
            channels=[
                {
                    "name": "webhook",
                    "enabled": True,
                    "config": {
                        "url": payload.url,
                        "secret": payload.secret,
                    },
                }
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
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Test a Slack Incoming Webhook integration."""
    try:
        config = ManagerConfig(
            channels=[
                {
                    "name": "slack",
                    "enabled": True,
                    "config": {
                        "webhook_url": payload.url,
                        "channel": payload.channel,
                    },
                }
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
