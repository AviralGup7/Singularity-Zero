from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any

from src.reporting.platforms.base import (
    SubmissionEnvelope,
    SubmissionResult,
    _BaseClient,
    resolve_base_url,
    to_envelope,
)

logger = logging.getLogger(__name__)


class MetaClient(_BaseClient):
    platform = "meta"

    def __init__(
        self,
        access_token: str | None = None,
        base_url: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.access_token = access_token or os.environ.get("META_APP_ACCESS_TOKEN", "")
        self.base_url = resolve_base_url(base_url, "META_BASE_URL", "https://graph.facebook.com")

    @property
    def ready(self) -> bool:
        return bool(self.access_token)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(
                platform=self.platform, ok=False, error="Meta credentials not configured"
            )
        env = to_envelope(finding)
        url = f"{self.base_url}/v1/whitehat/report"
        payload = {
            "title": env.title,
            "description": env.description,
            "severity": env.severity,
            "target": env.target_name,
        }
        try:
            client = await self._http()
            resp = await client.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {self.access_token}"},
            )
        except Exception as exc:
            logger.warning("%s submit failed: %s", self.platform, exc, exc_info=True)
            return SubmissionResult(platform=self.platform, ok=False, error=str(exc))
        if resp.status_code in {200, 201, 202}:
            body = resp.json() if resp.text else {}
            return SubmissionResult(
                platform=self.platform,
                ok=True,
                external_id=str(body.get("id", "")),
                url=str(body.get("url", "")),
                status_code=resp.status_code,
                raw_response=body,
            )
        return SubmissionResult(
            platform=self.platform, ok=False, status_code=resp.status_code, error=resp.text[:200]
        )


__all__ = [
    "MetaClient",
]
