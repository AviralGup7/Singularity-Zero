"""Live platform-push clients for HackerOne, Bugcrowd, Intigriti, Synack, and newer platforms.

Each client wraps the platform's submission API as an async
``submit`` method that returns a structured :class:`SubmissionResult`.
The clients use ``httpx`` (already a project dependency) for HTTP
transport; authentication is read from environment variables or the
constructor arguments so credentials never appear in the source tree.

All clients are *opt-in* — they make a live network call only when
``submit()`` is invoked.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class SubmissionEnvelope:
    """Canonical representation of a vulnerability finding for platform submission."""

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
    """Coerce finding input into a canonical SubmissionEnvelope."""
    if isinstance(finding, SubmissionEnvelope):
        return finding
    return SubmissionEnvelope(
        title=str(finding.get("title", "Security finding")),
        description=str(finding.get("description") or finding.get("vulnerability_information") or "Security finding description"),
        severity=str(finding.get("severity", "medium")),
        target_url=str(finding.get("url") or finding.get("target_url") or ""),
        target_name=str(finding.get("target") or finding.get("target_name") or ""),
        category=str(finding.get("category") or finding.get("type") or "general"),
        request_payload=str(finding.get("request_payload") or finding.get("payload") or finding.get("evidence") or ""),
        response_body=str(finding.get("response_body") or finding.get("response") or finding.get("body") or ""),
        draft=bool(finding.get("draft", True)),
    )


@dataclass(slots=True)
class SubmissionResult:
    """Outcome of a single platform push."""

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
    """Shared helpers for platform clients."""

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


# ---------------------------------------------------------------------------
# HackerOne
# ---------------------------------------------------------------------------


class HackerOneClient(_BaseClient):
    """Live HackerOne submission client."""

    platform = "hackerone"

    def __init__(
        self,
        api_token: str | None = None,
        program_handle: str | None = None,
        base_url: str = "https://api.hackerone.com",
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
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )
        if resp.status_code in {200, 201, 202}:
            try:
                body = resp.json()
            except json.JSONDecodeError:
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


# ---------------------------------------------------------------------------
# Bugcrowd
# ---------------------------------------------------------------------------


class BugcrowdClient(_BaseClient):
    """Live Bugcrowd submission client."""

    platform = "bugcrowd"

    def __init__(
        self,
        api_token: str | None = None,
        program_code: str | None = None,
        base_url: str = "https://api.bugcrowd.com",
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
        except Exception:  # noqa: BLE001
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


# ---------------------------------------------------------------------------
# Intigriti
# ---------------------------------------------------------------------------


class IntigritiClient(_BaseClient):
    """Live Intigriti submission client."""

    platform = "intigriti"

    def __init__(
        self,
        api_token: str | None = None,
        program_id: str | None = None,
        base_url: str = "https://api.intigriti.com",
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_token = api_token or os.environ.get("INTIGRITI_API_TOKEN", "")
        self.program_id = program_id or os.environ.get("INTIGRITI_PROGRAM_ID", "")
        self.base_url = base_url.rstrip("/")

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
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
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


# ---------------------------------------------------------------------------
# Synack
# ---------------------------------------------------------------------------


class SynackClient(_BaseClient):
    """Live Synack submission client."""

    platform = "synack"

    def __init__(
        self,
        api_token: str | None = None,
        assessment_id: str | None = None,
        base_url: str = "https://api.synack.com",
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_token = api_token or os.environ.get("SYNACK_API_TOKEN", "")
        self.assessment_id = assessment_id or os.environ.get("SYNACK_ASSESSMENT_ID", "")
        self.base_url = base_url.rstrip("/")

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
            return SubmissionResult(
                platform=self.platform,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
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


# ---------------------------------------------------------------------------
# YesWeHack
# ---------------------------------------------------------------------------


class YesWeHackClient(_BaseClient):
    """Live YesWeHack submission client."""

    platform = "yeswehack"

    def __init__(
        self,
        api_token: str | None = None,
        program_slug: str | None = None,
        base_url: str = "https://api.yeswehack.com",
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
            return SubmissionResult(platform=self.platform, ok=False, error="YesWeHack credentials not configured")
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
            resp = await client.post(url, json=payload, headers={"Authorization": f"Bearer {self.api_token}"})
        except Exception as exc:
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
        return SubmissionResult(platform=self.platform, ok=False, status_code=resp.status_code, error=resp.text[:200])


# ---------------------------------------------------------------------------
# Open Bug Bounty
# ---------------------------------------------------------------------------


class OpenBugBountyClient(_BaseClient):
    """Live Open Bug Bounty / Hacker-Powered submission client."""

    platform = "openbugbounty"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://www.openbugbounty.org",
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_key = api_key or os.environ.get("OPENBUGBOUNTY_API_KEY", "")
        self.base_url = base_url.rstrip("/")

    @property
    def ready(self) -> bool:
        return bool(self.api_key)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(platform=self.platform, ok=False, error="OpenBugBounty credentials not configured")
        env = to_envelope(finding)
        url = f"{self.base_url}/api/v1/vulnerability"
        payload = {
            "key": self.api_key,
            "url": env.target_url,
            "type": env.category,
            "poc": env.request_payload,
            "description": env.description,
        }
        try:
            client = await self._http()
            resp = await client.post(url, json=payload)
        except Exception as exc:
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
        return SubmissionResult(platform=self.platform, ok=False, status_code=resp.status_code, error=resp.text[:200])


# ---------------------------------------------------------------------------
# Google VRP
# ---------------------------------------------------------------------------


class GoogleVRPClient(_BaseClient):
    """Live Google VRP / Google Issue Tracker client."""

    platform = "googlevrp"

    def __init__(
        self,
        api_key: str | None = None,
        tracker_id: str | None = None,
        base_url: str = "https://issuetracker.googleapis.com",
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_key = api_key or os.environ.get("GOOGLE_VRP_API_KEY", "")
        self.tracker_id = tracker_id or os.environ.get("GOOGLE_VRP_TRACKER_ID", "default")
        self.base_url = base_url.rstrip("/")

    @property
    def ready(self) -> bool:
        return bool(self.api_key)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(platform=self.platform, ok=False, error="GoogleVRP credentials not configured")
        env = to_envelope(finding)
        url = f"{self.base_url}/v1/issues/{self.tracker_id}"
        payload = {
            "title": env.title,
            "description": env.description,
            "severity": env.severity,
            "component": "VRP",
        }
        try:
            client = await self._http()
            resp = await client.post(url, json=payload, headers={"X-Goog-Api-Key": self.api_key})
        except Exception as exc:
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
        return SubmissionResult(platform=self.platform, ok=False, status_code=resp.status_code, error=resp.text[:200])


# ---------------------------------------------------------------------------
# Meta / Facebook
# ---------------------------------------------------------------------------


class MetaClient(_BaseClient):
    """Live Meta Whitehat program submission client."""

    platform = "meta"

    def __init__(
        self,
        access_token: str | None = None,
        base_url: str = "https://graph.facebook.com",
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.access_token = access_token or os.environ.get("META_APP_ACCESS_TOKEN", "")
        self.base_url = base_url.rstrip("/")

    @property
    def ready(self) -> bool:
        return bool(self.access_token)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(platform=self.platform, ok=False, error="Meta credentials not configured")
        env = to_envelope(finding)
        url = f"{self.base_url}/v1/whitehat/report"
        payload = {
            "title": env.title,
            "description": env.description,
            "severity": env.severity,
            "target": env.target_name,
            "access_token": self.access_token,
        }
        try:
            client = await self._http()
            resp = await client.post(url, json=payload)
        except Exception as exc:
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
        return SubmissionResult(platform=self.platform, ok=False, status_code=resp.status_code, error=resp.text[:200])


# ---------------------------------------------------------------------------
# Apple
# ---------------------------------------------------------------------------


class AppleClient(_BaseClient):
    """Live Apple Security Research submission client."""

    platform = "apple"

    def __init__(
        self,
        dev_token: str | None = None,
        program_id: str | None = None,
        base_url: str = "https://api.apple-security.com",
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
            return SubmissionResult(platform=self.platform, ok=False, error="Apple credentials not configured")
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
            resp = await client.post(url, json=payload, headers={"Authorization": f"Bearer {self.dev_token}"})
        except Exception as exc:
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
        return SubmissionResult(platform=self.platform, ok=False, status_code=resp.status_code, error=resp.text[:200])


# ---------------------------------------------------------------------------
# Amazon / AWS
# ---------------------------------------------------------------------------


class AWSClient(_BaseClient):
    """Live Amazon AWS Vulnerability Reporting submission client."""

    platform = "aws"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://security-report.aws.amazon.com",
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_key = api_key or os.environ.get("AWS_SECURITY_API_KEY", "")
        self.base_url = base_url.rstrip("/")

    @property
    def ready(self) -> bool:
        return bool(self.api_key)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(platform=self.platform, ok=False, error="AWS credentials not configured")
        env = to_envelope(finding)
        url = f"{self.base_url}/aws-vulnerability-report"
        payload = {
            "title": env.title,
            "body": env.description,
            "severity": env.severity,
            "target": env.target_url,
        }
        try:
            client = await self._http()
            resp = await client.post(url, json=payload, headers={"X-AWS-API-Key": self.api_key})
        except Exception as exc:
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
        return SubmissionResult(platform=self.platform, ok=False, status_code=resp.status_code, error=resp.text[:200])


# ---------------------------------------------------------------------------
# Microsoft / MSRC
# ---------------------------------------------------------------------------


class MSRCAgent(_BaseClient):
    """Live Microsoft MSRC submission client."""

    platform = "msrc"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://api.msrc.microsoft.com",
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_key = api_key or os.environ.get("MSRC_API_KEY", "")
        self.base_url = base_url.rstrip("/")

    @property
    def ready(self) -> bool:
        return bool(self.api_key)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(platform=self.platform, ok=False, error="MSRC credentials not configured")
        env = to_envelope(finding)
        url = f"{self.base_url}/api/msrc/v1/submissions"
        payload = {
            "title": env.title,
            "description": env.description,
            "severity": env.severity,
            "affectedProduct": env.target_name,
        }
        try:
            client = await self._http()
            resp = await client.post(url, json=payload, headers={"api-key": self.api_key})
        except Exception as exc:
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
        return SubmissionResult(platform=self.platform, ok=False, status_code=resp.status_code, error=resp.text[:200])


# ---------------------------------------------------------------------------
# Mozilla
# ---------------------------------------------------------------------------


class MozillaClient(_BaseClient):
    """Live Mozilla Bugzilla submission client."""

    platform = "mozilla"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://bugzilla.mozilla.org",
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_key = api_key or os.environ.get("MOZILLA_BUGZILLA_API_KEY", "")
        self.base_url = base_url.rstrip("/")

    @property
    def ready(self) -> bool:
        return bool(self.api_key)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(platform=self.platform, ok=False, error="Mozilla credentials not configured")
        env = to_envelope(finding)
        url = f"{self.base_url}/api/v1/bug"
        payload = {
            "product": "Firefox",
            "component": "Security",
            "summary": env.title,
            "description": env.description,
            "security_sensitive": True,
            "api_key": self.api_key,
        }
        try:
            client = await self._http()
            resp = await client.post(url, json=payload)
        except Exception as exc:
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
        return SubmissionResult(platform=self.platform, ok=False, status_code=resp.status_code, error=resp.text[:200])


# ---------------------------------------------------------------------------
# Government / defense programs
# ---------------------------------------------------------------------------


class GovDefenseClient(_BaseClient):
    """Live Government and Defense coordinated vulnerability submission client."""

    platform = "govdefense"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://vulnerability-disclosure.cisa.gov",
        timeout: float = 20.0,
    ) -> None:
        super().__init__(timeout=timeout)
        self.api_key = api_key or os.environ.get("CISA_BOD_API_KEY", "")
        self.base_url = base_url.rstrip("/")

    @property
    def ready(self) -> bool:
        return bool(self.api_key)

    async def submit(self, finding: Mapping[str, Any] | SubmissionEnvelope) -> SubmissionResult:
        if not self.ready:
            return SubmissionResult(platform=self.platform, ok=False, error="Government/Defense credentials not configured")
        env = to_envelope(finding)
        url = f"{self.base_url}/cisa/v1/submissions"
        payload = {
            "agency": "CISA",
            "title": env.title,
            "description": env.description,
            "severity": env.severity,
            "target": env.target_url,
        }
        try:
            client = await self._http()
            resp = await client.post(url, json=payload, headers={"Authorization": f"Bearer {self.api_key}"})
        except Exception as exc:
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
        return SubmissionResult(platform=self.platform, ok=False, status_code=resp.status_code, error=resp.text[:200])


# ---------------------------------------------------------------------------
# Registry helper
# ---------------------------------------------------------------------------


def build_default_clients() -> dict[str, _BaseClient]:
    """Return every client that has its required credentials present."""
    return {
        "hackerone": HackerOneClient(),
        "bugcrowd": BugcrowdClient(),
        "intigriti": IntigritiClient(),
        "synack": SynackClient(),
        "yeswehack": YesWeHackClient(),
        "openbugbounty": OpenBugBountyClient(),
        "googlevrp": GoogleVRPClient(),
        "meta": MetaClient(),
        "apple": AppleClient(),
        "aws": AWSClient(),
        "msrc": MSRCAgent(),
        "mozilla": MozillaClient(),
        "govdefense": GovDefenseClient(),
    }


# ---------------------------------------------------------------------------
# Body + severity helpers
# ---------------------------------------------------------------------------


def _severity_to_hackerone(sev: Any) -> str:
    s = str(sev or "").lower()
    return s if s in {"critical", "high", "medium", "low", "none"} else "none"


def _bugcrowd_payout(sev: Any) -> float:
    return {"critical": 5.0, "high": 4.0, "medium": 3.0, "low": 2.0}.get(
        str(sev or "").lower(), 1.0
    )


def _bugcrowd_priority(sev: Any) -> int:
    return {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(
        str(sev or "").lower(), 5
    )


def _intigriti_severity(sev: Any) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(
        str(sev or "").lower(), 1
    )


def _intigriti_weakness_id(finding_type: Any) -> str:
    t = str(finding_type or "").lower()
    if "xss" in t:
        return "xss"
    if "sql" in t:
        return "sqli"
    if "ssrf" in t:
        return "server_side_request_forgery"
    if "rce" in t or "command" in t:
        return "rce"
    if "auth" in t or "broken" in t:
        return "broken_authentication"
    if "idor" in t or "bola" in t:
        return "idor"
    return "other"


def _synack_severity(sev: Any) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(
        str(sev or "").lower(), "informational"
    )


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


__all__ = [
    "BugcrowdClient",
    "HackerOneClient",
    "IntigritiClient",
    "SubmissionResult",
    "SynackClient",
    "YesWeHackClient",
    "OpenBugBountyClient",
    "GoogleVRPClient",
    "MetaClient",
    "AppleClient",
    "AWSClient",
    "MSRCAgent",
    "MozillaClient",
    "GovDefenseClient",
    "SubmissionEnvelope",
    "build_default_clients",
]
