import logging
from typing import Any, cast

import httpx
from pydantic import Field, HttpUrl

from src.infrastructure.notifications.base import (
    BaseNotifier,
    NotificationConfig,
    NotificationPayload,
    NotificationResult,
)

logger = logging.getLogger(__name__)


class WebhookConfig(NotificationConfig):
    url: HttpUrl
    method: str = Field(default="POST", pattern="^(GET|POST|PUT|PATCH)$")
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    payload_template: str | None = Field(default=None)
    secret: str | None = Field(default=None)
    verify_ssl: bool = Field(default=True)


class WebhookNotifier(BaseNotifier):
    def __init__(self, config: WebhookConfig) -> None:
        super().__init__(config, channel_name="webhook")
        self._webhook_config = config
        self._client = httpx.AsyncClient(
            timeout=config.timeout_seconds,
            verify=config.verify_ssl,
        )

    async def _do_send(self, payload: NotificationPayload) -> NotificationResult:
        headers = dict(self._webhook_config.headers)
        headers.setdefault("Content-Type", "application/json")

        if self._webhook_config.secret:
            import hashlib
            import hmac

            body_bytes = payload.model_dump_json().encode("utf-8")
            signature = hmac.new(
                self._webhook_config.secret.encode("utf-8"),
                body_bytes,
                hashlib.sha256,
            ).hexdigest()
            headers["X-Webhook-Signature"] = f"sha256={signature}"

        request_kwargs: dict[str, Any] = {
            "url": str(self._webhook_config.url),
            "headers": headers,
        }

        if self._webhook_config.query_params:
            request_kwargs["params"] = self._webhook_config.query_params

        method = self._webhook_config.method.upper()

        if method in ("POST", "PUT", "PATCH"):
            request_kwargs["json"] = self._build_payload(payload)
            if method == "POST":
                response = await self._client.post(**request_kwargs)
            elif method == "PUT":
                response = await self._client.put(**request_kwargs)
            else:
                response = await self._client.patch(**request_kwargs)
        else:
            response = await self._client.get(**request_kwargs)

        if response.status_code < 400:
            return NotificationResult(
                success=True,
                channel=self._channel_name,
                event=payload.event.value,
                priority=payload.priority.value,
                response_data={
                    "status_code": response.status_code,
                    "body": self._safe_response_body(response),
                },
            )

        raise httpx.HTTPStatusError(
            f"Webhook returned {response.status_code}: {response.text[:200]}",
            request=response.request,
            response=response,
        )

    def _build_payload(self, payload: NotificationPayload) -> dict[str, Any]:
        if self._webhook_config.payload_template:
            return self._render_template(payload)
        return payload.model_dump(mode="json")

    def _render_template(self, payload: NotificationPayload) -> dict[str, Any]:
        template = self._webhook_config.payload_template
        context = payload.model_dump(mode="json")
        context["priority_upper"] = payload.priority.value.upper()
        context["event_upper"] = payload.event.value.upper()
        context["timestamp_iso"] = payload.timestamp.isoformat()

        result: dict[str, Any] = {}
        import json as _json

        try:
            result = _json.loads(str(template))
        except _json.JSONDecodeError:
            result = {"message": str(template)}

        def _replace_placeholders(obj: Any) -> Any:
            if isinstance(obj, str):
                result_str = obj
                for key, value in context.items():
                    placeholder = "{{" + key + "}}"
                    result_str = result_str.replace(placeholder, str(value))
                return result_str
            if isinstance(obj, dict):
                return {k: _replace_placeholders(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_replace_placeholders(item) for item in obj]
            return obj

        return cast(dict[str, Any], _replace_placeholders(result))

    def _safe_response_body(self, response: httpx.Response) -> str:
        try:
            return response.text[:500]
        except Exception:
            return ""

    async def close(self) -> None:
        await self._client.aclose()
