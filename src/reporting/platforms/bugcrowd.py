from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

import httpx

from src.reporting.platforms.base import (
    _BaseClient,
    SubmissionEnvelope,
    SubmissionResult,
    logger,
    to_envelope,
)


def _bugcrowd_payout(sev: Any) -> float:
    return {"critical": 5.0, "high": 4.0, "medium": 3.0, "low": 2.0}.get(
        str(sev or "").lower(), 1.0
    )


def _bugcrowd_priority(sev: Any) -> int:
    return {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(str(sev or "").lower(), 5)


def _build_bugcrowd_body(env: SubmissionEnvelope) -> str:
    parts = [
        "## Description",
        env.description,
        "",
        "## Reproduction Steps",
        "1. Navigate to the affected URL below",
        "2. Use the request/response pair provided",
        "3. Observe the behaviour described above",
        "",
        "## Impact",
        env.description,
        "",
        "## Remediation Plan",
        "Triage with the engineering team to determine the appropriate fix for this class of issue.",
        "",
        f"**Affected URL:** {env.target_url or '—'}",
        f"**Target:** {env.target_name or '—'}",
    ]
    return "\n".join(str(p) for p in parts)


class BugcrowdClient(_BaseClient):
    platform = "bugcrowd"

    def __init__(
        self,
        api_token: str | None = None,
        program_code: str | None = None,
        base_url: str = os.environ.get("BUGCROWD_BASE_URL", "https://api.bugcrowd.com"),
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_token = api_token or os.environ.get("BUGCROWD_API_TOKEN", "")
        self.program_code = program_code or os.environ.get("BUGCROWD_PROGRAM_CODE", "")
        self.base_url = base_url.rstrip("/")

    @property
    def ready(self) -> bool:
        return bool(self.api_token and self.program_code)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error="Bugcrowd credentials not configured",
            )
        env = to_envelope(finding)
        url = f"{self.base_url}/programs/{self.program_code}/submissions"
        payload = {
            "title": str(env.title)[:140],
            "description": _build_bugcrowd_body(env),
            "severity": int(_bugcrowd_payout(env.severity)),
            "priority": _bugcrowd_priority(env.severity),
            "category": str(env.category),
            "target_url": str(env.target_url),
        }
        try:
            client = await self._http()
            resp = await client.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Accept": "application/vnd.bugcrowd+json",
                    "Content-Type": "application/json",
                },
            )
        except (TimeoutError, httpx.RequestError) as exc:
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )
        try:
            body = resp.json()
        except Exception:
            logger.warning("Failed to parse Bugcrowd response JSON", exc_info=True)
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
            error=f"Bugcrowd returned {resp.status_code}: {resp.text[:200]}",
        )


__all__ = [
    "BugcrowdClient",
]
