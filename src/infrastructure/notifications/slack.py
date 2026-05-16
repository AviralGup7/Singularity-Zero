import logging
from typing import Any

import httpx
from pydantic import Field, HttpUrl

from src.infrastructure.notifications.base import (
    BaseNotifier,
    NotificationConfig,
    NotificationPayload,
    NotificationResult,
)

logger = logging.getLogger(__name__)


class SlackConfig(NotificationConfig):
    webhook_url: HttpUrl
    channel: str | None = Field(default=None)
    username: str = Field(default="Cyber Security Pipeline")
    icon_emoji: str = Field(default=":shield:")
    icon_url: str | None = Field(default=None)
    mention_on_critical: list[str] = Field(default_factory=list)


class SlackNotifier(BaseNotifier):
    def __init__(self, config: SlackConfig) -> None:
        super().__init__(config, channel_name="slack")
        self._slack_config = config
        self._client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            headers={"Content-Type": "application/json"},
        )

    async def _do_send(self, payload: NotificationPayload) -> NotificationResult:
        blocks = self._build_blocks(payload)
        body: dict[str, Any] = {
            "blocks": blocks,
            "username": self._slack_config.username,
        }

        if self._slack_config.channel:
            body["channel"] = self._slack_config.channel

        if self._slack_config.icon_emoji:
            body["icon_emoji"] = self._slack_config.icon_emoji

        if self._slack_config.icon_url:
            body["icon_url"] = self._slack_config.icon_url

        text = self._build_fallback_text(payload)
        body["text"] = text

        if payload.priority.value == "critical" and self._slack_config.mention_on_critical:
            mentions = " ".join(f"<@{user}>" for user in self._slack_config.mention_on_critical)
            body["text"] = f"{mentions} {text}"

        response = await self._client.post(
            str(self._slack_config.webhook_url),
            json=body,
        )

        if response.status_code == 200:
            return NotificationResult(
                success=True,
                channel=self._channel_name,
                event=payload.event.value,
                priority=payload.priority.value,
                response_data={"status_code": response.status_code},
            )

        raise httpx.HTTPStatusError(
            f"Slack webhook returned {response.status_code}",
            request=response.request,
            response=response,
        )

    def _build_blocks(self, payload: NotificationPayload) -> list[dict[str, Any]]:
        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": self._format_header(payload),
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Event:*\n{payload.event.value}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Priority:*\n{payload.priority.value.upper()}",
                    },
                    {"type": "mrkdwn", "text": f"*Source:*\n{payload.source}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:*\n{payload.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Message:*\n{payload.message}"},
            },
        ]

        if payload.correlation_id:
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"`Correlation ID: {payload.correlation_id}`",
                        },
                    ],
                },
            )

        if self._slack_config.include_metadata and payload.metadata:
            metadata_text = "\n".join(f"• `{k}`: `{v}`" for k, v in payload.metadata.items())
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Metadata:*\n{metadata_text}"},
                },
            )

        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"_{payload.source} | {payload.timestamp.isoformat()}_",
                },
            },
        )

        return blocks

    def _build_fallback_text(self, payload: NotificationPayload) -> str:
        return f"[{payload.priority.value.upper()}] {payload.title}: {payload.message}"

    def _format_header(self, payload: NotificationPayload) -> str:
        icons = {
            "low": "ℹ️",
            "medium": "⚠️",
            "high": "🚨",
            "critical": "🔴 CRITICAL",
        }
        icon = icons.get(payload.priority.value, "📢")
        return f"{icon} {payload.title}"

    async def close(self) -> None:
        await self._client.aclose()
