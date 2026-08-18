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

logger = logging.getLogger(__name__)


def _synack_severity(sev: Any) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(
        str(sev or "").lower(), "informational"
    )


def _build_synack_body(env: SubmissionEnvelope) -> str:
    parts = [
        "## Vulnerability Description",
        env.description,
        "",
        "## Reproduction Steps",
        "1. Navigate to the affected URL below",
        "2. Use the request/response pair provided",
        "3. Observe the behaviour described above",
        "",
        "## Business Impact",
        env.description,
        "",
        "## Suggested Fix",
        "Triage with the engineering team to determine the appropriate fix for this class of issue.",
        "",
        f"**Affected URL:** {env.target_url or '—'}",
        f"**Target:** {env.target_name or '—'}",
    ]
    return "\n".join(str(p) for p in parts)


class SynackClient(_BaseClient):
    platform = "synack"

    def __init__(
        self,
        api_token: str | None = None,
        assessment_id: str | None = None,
        base_url: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_token = api_token or os.environ.get("SYNACK_API_TOKEN", "")
        self.assessment_id = assessment_id or os.environ.get("SYNACK_ASSESSMENT_ID", "")
        self.base_url = resolve_base_url(base_url, "SYNACK_BASE_URL", "https://api.synack.com")

    @property
    def ready(self) -> bool:
        return bool(self.api_token and self.assessment_id)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error="Synack credentials not configured",
            )
        env = to_envelope(finding)
        url = f"{self.base_url}/api/assessment/{self.assessment_id}/vulnerabilities"
        payload = {
            "title": str(env.title)[:200],
            "description": _build_synack_body(env),
            "severity": _synack_severity(env.severity),
            "vulnerability_category": str(env.category),
        }
        try:
            client = await self._http()
            resp = await client.post(
                url,
                json=payload,
                headers={
                    "Authorization": self.api_token,
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
            logger.warning("Failed to parse Synack response JSON", exc_info=True)
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
            error=f"Synack returned {resp.status_code}: {resp.text[:200]}",
        )


__all__ = [
    "SynackClient",
]
