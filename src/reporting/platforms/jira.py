"""Jira Cloud & Server issue creation integration."""

from __future__ import annotations

import base64
import os
from collections.abc import Mapping
from typing import Any

from src.reporting.platforms.base import (
    SubmissionEnvelope,
    SubmissionResult,
    _BaseClient,
    logger,
    resolve_base_url,
    to_envelope,
)


def _map_jira_priority(sev: str) -> str:
    mapping = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }
    return mapping.get(sev.lower(), "Medium")


class JiraClient(_BaseClient):
    platform = "jira"

    def __init__(
        self,
        base_url: str | None = None,
        email: str | None = None,
        api_token: str | None = None,
        project_key: str | None = None,
        issue_type: str | None = None,
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.base_url = resolve_base_url(base_url, "JIRA_BASE_URL", "")
        self.email = email or os.environ.get("JIRA_EMAIL", "")
        self.api_token = api_token or os.environ.get("JIRA_API_TOKEN", "")
        self.project_key = project_key or os.environ.get("JIRA_PROJECT_KEY", "")
        self.issue_type = issue_type or os.environ.get("JIRA_ISSUE_TYPE", "Bug")

    @property
    def ready(self) -> bool:
        return bool(
            self.base_url
            and self.api_token
            and (self.email or ":" in self.api_token)
            and self.project_key
        )

    def _auth_header(self) -> str:
        if self.email:
            credentials = f"{self.email}:{self.api_token}"
        else:
            credentials = self.api_token
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        env = to_envelope(finding)
        if not self.ready:
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error="Jira client credentials/project_key not configured",
            )

        endpoint = f"{self.base_url}/rest/api/3/issue"
        headers = {
            "Authorization": self._auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        description_text = (
            f"*Target URL:* {env.target_url or 'N/A'}\n"
            f"*Category:* {env.category}\n"
            f"*Severity:* {env.severity.upper()}\n\n"
            f"h3. Vulnerability Description\n{env.description}\n\n"
            f"h3. Evidence / Payload\n{env.request_payload or 'N/A'}"
        )

        adf_description = {
            "version": 1,
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": description_text}],
                }
            ],
        }

        payload: dict[str, Any] = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[{env.severity.upper()}] {env.title}",
                "description": adf_description,
                "issuetype": {"name": self.issue_type},
                "priority": {"name": _map_jira_priority(env.severity)},
                "labels": ["security", "vulnerability", env.category.lower().replace(" ", "-")],
            }
        }

        try:
            client = await self._http()
            resp = await client.post(endpoint, json=payload, headers=headers)
            status_code = resp.status_code

            if status_code in (200, 201):
                data = resp.json()
                issue_key = data.get("key", "")
                issue_url = f"{self.base_url}/browse/{issue_key}" if issue_key else ""
                return SubmissionResult(
                    platform=self.platform,
                    ok=True,
                    external_id=issue_key,
                    url=issue_url,
                    status_code=status_code,
                    raw_response=data,
                )

            if status_code == 400:
                payload["fields"]["description"] = description_text
                v2_endpoint = f"{self.base_url}/rest/api/2/issue"
                v2_resp = await client.post(v2_endpoint, json=payload, headers=headers)
                if v2_resp.status_code in (200, 201):
                    v2_data = v2_resp.json()
                    v2_key = v2_data.get("key", "")
                    return SubmissionResult(
                        platform=self.platform,
                        ok=True,
                        external_id=v2_key,
                        url=f"{self.base_url}/browse/{v2_key}" if v2_key else "",
                        status_code=v2_resp.status_code,
                        raw_response=v2_data,
                    )

            error_msg = f"Jira API error {status_code}: {resp.text[:300]}"
            logger.warning("Jira submission failed: %s", error_msg)
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error=error_msg,
                status_code=status_code,
            )
        except Exception as exc:
            logger.exception("Jira submission encountered unexpected exception: %s", exc)
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error=str(exc),
            )
