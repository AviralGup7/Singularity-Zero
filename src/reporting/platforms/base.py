from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SubmissionEnvelope:
    title: str
    description: str
    severity: str
    target_url: str
    target_name: str
    category: str
    request_payload: str = ""
    response_body: str = ""
    draft: bool = True


def to_envelope(finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionEnvelope:
    if isinstance(finding, SubmissionEnvelope):
        return finding
    return SubmissionEnvelope(
        title=str(finding.get("title", "Security finding")),
        description=str(
            finding.get("description")
            or finding.get("vulnerability_information")
            or "Security finding description"
        ),
        severity=str(finding.get("severity", "medium")),
        target_url=str(finding.get("url") or finding.get("target_url") or ""),
        target_name=str(finding.get("target") or finding.get("target_name") or ""),
        category=str(finding.get("category") or finding.get("type") or "general"),
        request_payload=str(
            finding.get("request_payload")
            or finding.get("payload")
            or finding.get("evidence")
            or ""
        ),
        response_body=str(
            finding.get("response_body") or finding.get("response") or finding.get("body") or ""
        ),
        draft=bool(finding.get("draft", True)),
    )


@dataclass(slots=True)
class SubmissionResult:
    platform: str
    ok: bool
    external_id: str = ""
    url: str = ""
    error: str = ""
    status_code: int = 0
    raw_response: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "ok": self.ok,
            "external_id": self.external_id,
            "url": self.url,
            "error": self.error,
            "status_code": self.status_code,
            "raw_response": dict(self.raw_response),
        }


class _BaseClient:
    platform: str = "base"

    def __init__(self, *, timeout: float = 20.0) -> None:
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> _BaseClient:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        await self.aclose()


__all__ = [
    "SubmissionEnvelope",
    "SubmissionResult",
    "_BaseClient",
    "to_envelope",
]
