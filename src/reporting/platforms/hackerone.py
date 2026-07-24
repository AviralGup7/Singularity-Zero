from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

import httpx

from src.reporting.platforms.base import (
    SubmissionEnvelope,
    SubmissionResult,
    _BaseClient,
    logger,
    to_envelope,
)


def _severity_to_hackerone(sev: Any) -> str:
    s = str(sev or "").lower()
    return s if s in {"critical", "high", "medium", "low", "none"} else "none"


def _build_hackerone_body(env: SubmissionEnvelope) -> str:
    parts = [
        env.description,
        "",
        f"**Affected URL:** {env.target_url or '—'}",
        f"**Target:** {env.target_name or '—'}",
        f"**Severity:** {env.severity or '—'}",
        f"**Weakness:** {env.category or '—'}",
    ]
    return "\n".join(str(p) for p in parts)[:9000]


class HackerOneClient(_BaseClient):
    platform = "hackerone"

    def __init__(
        self,
        api_token: str | None = None,
        program_handle: str | None = None,
        base_url: str = os.environ.get("HACKERONE_BASE_URL", "https://api.hackerone.com"),
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_token = api_token or os.environ.get("HACKERONE_API_TOKEN", "")
        self.program_handle = program_handle or os.environ.get("HACKERONE_PROGRAM_HANDLE", "")
        self.base_url = base_url.rstrip("/")

    @property
    def ready(self) -> bool:
        return bool(self.api_token and self.program_handle)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error="HackerOne credentials not configured",
            )
        env = to_envelope(finding)
        url = f"{self.base_url}/v1/hacktivity/teams/{self.program_handle}/reports"
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": str(env.title)[:140],
                    "severity_rating": _severity_to_hackerone(env.severity),
                    "vulnerability_information": _build_hackerone_body(env),
                },
            }
        }
        try:
            client = await self._http()
            resp = await client.post(
                url,
                json=payload,
                auth=(self.api_token, ""),
                headers={"Accept": "application/json"},
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
        if resp.status_code in {200, 201, 202}:
            try:
                body = resp.json()
            except Exception:
                logger.warning("Failed to parse HackerOne response JSON", exc_info=True)
                body = {}
            return SubmissionResult(
                platform=self.platform,
                ok=True,
                external_id=str(body.get("data", {}).get("id", "")),
                url=str(body.get("data", {}).get("attributes", {}).get("url", "")),
                status_code=resp.status_code,
                raw_response=body if isinstance(body, dict) else {},
            )
        return SubmissionResult(
            platform=self.platform,
            ok=False,
            status_code=resp.status_code,
            error=f"HackerOne returned {resp.status_code}: {resp.text[:200]}",
        )


__all__ = [
    "HackerOneClient",
]
