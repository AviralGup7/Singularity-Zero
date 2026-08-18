from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any

import httpx

from src.reporting.platforms.base import (
    SubmissionEnvelope,
    SubmissionResult,
    _BaseClient,
    resolve_base_url,
    to_envelope,
)
from src.reporting.sarif_exporter import _intigriti_weakness_id

logger = logging.getLogger(__name__)


def _intigriti_severity(sev: Any) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(str(sev or "").lower(), 1)


def _build_intigriti_body(env: SubmissionEnvelope) -> str:
    parts = [
        "## Description",
        env.description,
        "",
        "## Steps to Reproduce",
        "1. Navigate to the affected URL below",
        "2. Use the request/response pair provided",
        "3. Observe the behaviour described above",
        "",
        "## Impact",
        env.description,
        "",
        "## Remediation",
        "Triage with the engineering team to determine the appropriate fix for this class of issue.",
        "",
        "## Mitigation",
        "Apply the remediation described above; if a patch cannot be deployed immediately, consider rate-limiting or blocking the affected endpoint as a temporary mitigation.",
        "",
        f"**Affected URL:** {env.target_url or '—'}",
    ]
    return "\n".join(str(p) for p in parts)


class IntigritiClient(_BaseClient):
    platform = "intigriti"

    def __init__(
        self,
        api_token: str | None = None,
        program_id: str | None = None,
        base_url: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_token = api_token or os.environ.get("INTIGRITI_API_TOKEN", "")
        self.program_id = program_id or os.environ.get("INTIGRITI_PROGRAM_ID", "")
        self.base_url = resolve_base_url(
            base_url, "INTIGRITI_BASE_URL", "https://api.intigriti.com"
        )

    @property
    def ready(self) -> bool:
        return bool(self.api_token and self.program_id)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error="Intigriti credentials not configured",
            )
        env = to_envelope(finding)
        url = f"{self.base_url}/api/submission/{self.program_id}"
        payload = {
            "title": str(env.title)[:140],
            "description": _build_intigriti_body(env),
            "severity": _intigriti_severity(env.severity),
            "weakness": {"id": _intigriti_weakness_id(env.category)},
        }
        try:
            client = await self._http()
            resp = await client.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
        except (TimeoutError, httpx.RequestError) as exc:
            safe_error = (
                str(exc).replace(self.api_token, "[REDACTED]") if self.api_token else str(exc)
            )
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error=f"{type(exc).__name__}: {safe_error}",
            )
        try:
            body = resp.json()
        except Exception:
            logger.warning("Failed to parse Intigriti response JSON", exc_info=True)
            body = {}
        if resp.status_code in {200, 201, 202}:
            return SubmissionResult(
                platform=self.platform,
                ok=True,
                external_id=str(body.get("id", "")),
                url=str(body.get("url", "")),
                status_code=resp.status_code,
                raw_response=body if isinstance(body, dict) else {},
            )
        return SubmissionResult(
            platform=self.platform,
            ok=False,
            status_code=resp.status_code,
            error=f"Intigriti returned {resp.status_code}: {resp.text[:200]}",
        )


__all__ = [
    "IntigritiClient",
]
