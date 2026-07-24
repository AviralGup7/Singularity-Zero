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


class YesWeHackClient(_BaseClient):
    platform = "yeswehack"

    def __init__(
        self,
        api_token: str | None = None,
        program_slug: str | None = None,
        base_url: str = os.environ.get("YESWEHACK_BASE_URL", "https://api.yeswehack.com"),
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_token = api_token or os.environ.get("YESWEHACK_API_TOKEN", "")
        self.program_slug = program_slug or os.environ.get("YESWEHACK_PROGRAM_SLUG", "")
        self.base_url = base_url.rstrip("/")

    @property
    def ready(self) -> bool:
        return bool(self.api_token and self.program_slug)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(
                platform=self.platform, ok=False, error="YesWeHack credentials not configured"
            )
        env = to_envelope(finding)
        url = f"{self.base_url}/api/programs/{self.program_slug}/reports"
        payload = {
            "title": env.title,
            "description": env.description,
            "cvss": env.severity,
            "bug_type": env.category,
            "scope": env.target_url,
        }
        try:
            client = await self._http()
            resp = await client.post(
                url, json=payload, headers={"Authorization": f"Bearer {self.api_token}"}
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
    "YesWeHackClient",
]
