"""ServiceNow incident & vulnerability entry integration."""

from __future__ import annotations

import base64
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


def _map_servicenow_impact_urgency(sev: str) -> tuple[str, str]:
    mapping = {
        "critical": ("1", "1"),  # Impact 1 (High), Urgency 1 (High) -> Priority 1 (Critical)
        "high": ("1", "2"),      # Priority 2 (High)
        "medium": ("2", "2"),    # Priority 3 (Moderate)
        "low": ("3", "2"),       # Priority 4 (Low)
        "info": ("3", "3"),      # Priority 5 (Planning)
    }
    return mapping.get(sev.lower(), ("2", "2"))


class ServiceNowClient(_BaseClient):
    platform = "servicenow"

    def __init__(
        self,
        instance_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        table_name: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.base_url = resolve_base_url(instance_url, "SERVICENOW_INSTANCE_URL", "")
        self.username = username or os.environ.get("SERVICENOW_USERNAME", "")
        self.password = password or os.environ.get("SERVICENOW_PASSWORD", "")
        self.table_name = table_name or os.environ.get("SERVICENOW_TABLE", "incident")

    @property
    def ready(self) -> bool:
        return bool(self.base_url and self.username and self.password)

    def _auth_header(self) -> str:
        credentials = f"{self.username}:{self.password}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        env = to_envelope(finding)
        if not self.ready:
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error="ServiceNow client credentials not configured",
            )

        endpoint = f"{self.base_url}/api/now/table/{self.table_name}"
        headers = {
            "Authorization": self._auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        impact, urgency = _map_servicenow_impact_urgency(env.severity)

        payload: dict[str, Any] = {
            "short_description": f"[{env.severity.upper()}] Security Finding: {env.title}",
            "description": (
                f"Target URL: {env.target_url or 'N/A'}\n"
                f"Category: {env.category}\n"
                f"Severity: {env.severity.upper()}\n\n"
                f"Description:\n{env.description}\n\n"
                f"Evidence / Payload:\n{env.request_payload or 'N/A'}\n"
            ),
            "impact": impact,
            "urgency": urgency,
            "category": "Security",
            "subcategory": env.category,
        }

        try:
            client = await self._http()
            resp = await client.post(endpoint, json=payload, headers=headers)
            status_code = resp.status_code

            if status_code in (200, 201):
                data = resp.json().get("result", {})
                sys_id = data.get("sys_id", "")
                number = data.get("number", sys_id)
                record_url = f"{self.base_url}/nav_to.do?uri={self.table_name}.do?sys_id={sys_id}" if sys_id else ""
                return SubmissionResult(
                    platform=self.platform,
                    ok=True,
                    external_id=number,
                    url=record_url,
                    status_code=status_code,
                    raw_response=data,
                )

            error_msg = f"ServiceNow Table API error {status_code}: {resp.text[:300]}"
            logger.warning("ServiceNow submission failed: %s", error_msg)
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error=error_msg,
                status_code=status_code,
            )
        except Exception as exc:
            logger.exception("ServiceNow submission encountered unexpected exception: %s", exc)
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error=str(exc),
            )
