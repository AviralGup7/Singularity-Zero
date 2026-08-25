"""DefectDojo v2 findings integration."""

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
    resolve_base_url,
    to_envelope,
)


def _map_defectdojo_severity(sev: str) -> str:
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }
    return mapping.get(sev.lower(), "Medium")


class DefectDojoClient(_BaseClient):
    platform = "defectdojo"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        test_id: int | str | None = None,
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.base_url = resolve_base_url(base_url, "DEFECTDOJO_URL", "")
        self.api_key = api_key or os.environ.get("DEFECTDOJO_API_KEY", "")
        raw_test_id = test_id or os.environ.get("DEFECTDOJO_TEST_ID", "1")
        try:
            self.test_id = int(raw_test_id)
        except (TypeError, ValueError):
            self.test_id = 1

    @property
    def ready(self) -> bool:
        return bool(self.base_url and self.api_key)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        env = to_envelope(finding)
        if not self.ready:
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error="DefectDojo URL / API key not configured",
            )

        endpoint = f"{self.base_url}/api/v2/findings/"
        headers = {
            "Authorization": f"Token {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        severity = _map_defectdojo_severity(env.severity)

        payload: dict[str, Any] = {
            "title": env.title,
            "description": env.description,
            "severity": severity,
            "test": self.test_id,
            "active": True,
            "verified": not env.draft,
            "numerical_severity": {"Critical": "S0", "High": "S1", "Medium": "S2", "Low": "S3", "Info": "S4"}.get(severity, "S2"),
            "steps_to_reproduce": env.request_payload or "See scan logs for reproduction details.",
            "references": env.target_url,
            "tags": ["automated-scan", env.category.lower().replace(" ", "-")],
        }

        try:
            client = await self._http()
            resp = await client.post(endpoint, json=payload, headers=headers)
            status_code = resp.status_code

            if status_code in (200, 201):
                data = resp.json()
                finding_id = str(data.get("id", ""))
                finding_url = f"{self.base_url}/finding/{finding_id}" if finding_id else ""
                return SubmissionResult(
                    platform=self.platform,
                    ok=True,
                    external_id=finding_id,
                    url=finding_url,
                    status_code=status_code,
                    raw_response=data,
                )

            error_msg = f"DefectDojo API error {status_code}: {resp.text[:300]}"
            logger.warning("DefectDojo submission failed: %s", error_msg)
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error=error_msg,
                status_code=status_code,
            )
        except Exception as exc:
            logger.exception("DefectDojo submission encountered unexpected exception: %s", exc)
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error=str(exc),
            )
