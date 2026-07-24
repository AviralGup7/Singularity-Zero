from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any

from src.reporting.platforms.base import (
    SubmissionEnvelope,
    SubmissionResult,
    _BaseClient,
    to_envelope,
)

logger = logging.getLogger(__name__)


class AppleClient(_BaseClient):
    platform = "apple"

    def __init__(
        self,
        dev_token: str | None = None,
        program_id: str | None = None,
        base_url: str = os.environ.get("APPLE_BASE_URL", "https://api.apple-security.com"),
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.dev_token = dev_token or os.environ.get("APPLE_DEVELOPER_TOKEN", "")
        self.program_id = program_id or os.environ.get("APPLE_PROGRAM_ID", "default")
        self.base_url = base_url.rstrip("/")

    @property
    def ready(self) -> bool:
        return bool(self.dev_token)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(
                platform=self.platform, ok=False, error="Apple credentials not configured"
            )
        env = to_envelope(finding)
        url = f"{self.base_url}/api/v1/security-reports"
        payload = {
            "title": env.title,
            "description": env.description,
            "severity": env.severity,
            "program_id": self.program_id,
        }
        try:
            client = await self._http()
            resp = await client.post(
                url, json=payload, headers={"Authorization": f"Bearer {self.dev_token}"}
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
    "AppleClient",
]
