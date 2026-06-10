"""Ticket-creator plugin family.

Adds a new ``ticket_creator`` plugin kind to the pipeline's plugin
registry.  Backed by three skeleton implementations:

* :class:`HackerOneTicketCreator` — posts to ``/v1/reports`` (HackerOne
  Hacktivity API).  Skeleton only: requests real auth and base URL
  from config, never makes live calls in unit tests.
* :class:`BugcrowdTicketCreator` — posts to ``/submissions`` (Bugcrowd
  VRT-aware submission endpoint).
* :class:`JiraTicketCreator` — POSTs to ``/rest/api/3/issue`` (Jira
  Cloud REST API v3).

All three are gated by a ``ticket_creation_enabled`` config flag and
a per-creator ``enabled`` flag.  Skeletons are deliberately minimal
and ship with no live network calls — they emit a structured
``TicketResult`` describing what *would* happen.  Operators are
expected to wire the ``requests`` POSTs in their deployment and supply
credentials via the configuration system.

A registry helper :func:`create_ticket_creators_from_config` builds
the full set of creators from a pipeline config dict.
"""
from __future__ import annotations


import hashlib
import logging
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from src.core.plugins import register_plugin

logger = logging.getLogger(__name__)


TICKET_CREATOR = "ticket_creator"


SUPPORTED_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "info"})


@dataclass(frozen=True, slots=True)
class TicketResult:
    """Outcome of a single ticket-creation attempt."""

    platform: str
    finding_key: str
    ok: bool
    external_id: str = ""
    url: str = ""
    error: str = ""
    status_code: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "finding_key": self.finding_key,
            "ok": self.ok,
            "external_id": self.external_id,
            "url": self.url,
            "error": self.error,
            "status_code": self.status_code,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class TicketCreatorBase:
    """Common behaviour for ticket creators.

    Subclasses must implement :meth:`_platform_name` and
    :meth:`_do_create`.  The base class handles severity gating,
    finding-key fingerprinting, and disabled-by-config short-circuits.
    """

    enabled: bool = False
    min_severity: str = "high"
    platform_label: str = "base"

    def __post_init__(self) -> None:
        if str(self.min_severity).lower() not in SUPPORTED_SEVERITIES:
            raise ValueError(
                f"min_severity must be one of {sorted(SUPPORTED_SEVERITIES)}, "
                f"got {self.min_severity!r}"
            )

    @property
    def severity_rank(self) -> int:
        order = ("info", "low", "medium", "high", "critical")
        return order.index(str(self.min_severity).lower())

    def _platform_name(self) -> str:
        return self.platform_label

    def _finding_fingerprint(self, finding: Mapping[str, Any]) -> str:
        """Stable SHA-1 fingerprint of a finding for dedup at the ticket store."""
        url = str(finding.get("url", ""))
        category = str(finding.get("category", ""))
        title = str(finding.get("title", ""))
        payload = f"{category}|{url}|{title}".encode()
        return hashlib.sha1(payload).hexdigest()

    def _should_create(self, finding: Mapping[str, Any]) -> bool:
        if not self.enabled:
            return False
        sev = str(finding.get("severity", "info")).lower()
        if sev not in SUPPORTED_SEVERITIES:
            sev = "info"
        order = ("info", "low", "medium", "high", "critical")
        return order.index(sev) >= self.severity_rank

    def _do_create(
        self, finding: Mapping[str, Any], review_brief: str
    ) -> TicketResult:
        raise NotImplementedError

    def create_ticket(
        self, finding: Mapping[str, Any], review_brief: str
    ) -> TicketResult:
        if not self._should_create(finding):
            return TicketResult(
                platform=self._platform_name(),
                finding_key=self._finding_fingerprint(finding),
                ok=False,
                error=f"finding severity {finding.get('severity', 'info')!r} below threshold {self.min_severity!r}",
            )
        try:
            return self._do_create(finding, review_brief)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Ticket creator %s raised for finding %s: %s",
                self._platform_name(),
                finding.get("url", ""),
                exc,
            )
            return TicketResult(
                platform=self._platform_name(),
                finding_key=self._finding_fingerprint(finding),
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
            )


@dataclass(slots=True)
class HackerOneTicketCreator(TicketCreatorBase):
    """Skeleton HackerOne report creator.

    Disabled by default.  Operators set ``HACKERONE_API_TOKEN`` and
    ``HACKERONE_BASE_URL`` in the environment (or pass them via the
    pipeline config) before flipping ``enabled=True``.  The skeleton
    returns a structured :class:`TicketResult` describing what the
    eventual POST would look like, without making live network calls.
    """

    api_token: str = ""
    program_handle: str = ""
    base_url: str = "https://api.hackerone.com"

    def __post_init__(self) -> None:
        TicketCreatorBase.__post_init__(self)
        self.platform_label = "hackerone"

    def _do_create(
        self, finding: Mapping[str, Any], review_brief: str
    ) -> TicketResult:
        if not self.api_token:
            return TicketResult(
                platform="hackerone",
                finding_key=self._finding_fingerprint(finding),
                ok=False,
                error="HACKERONE_API_TOKEN not configured",
            )
        if not self.program_handle:
            return TicketResult(
                platform="hackerone",
                finding_key=self._finding_fingerprint(finding),
                ok=False,
                error="program_handle not configured",
            )
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": str(finding.get("title", "Security finding"))[:140],
                    "severity_rating": _severity_to_hackerone(
                        finding.get("severity", "info")
                    ),
                    "vulnerability_information": review_brief[:9_000],
                },
            }
        }
        logger.info(
            "HackerOneTicketCreator: would POST to %s/v1/reports for program %s",
            self.base_url,
            self.program_handle,
        )
        return TicketResult(
            platform="hackerone",
            finding_key=self._finding_fingerprint(finding),
            ok=True,
            url=f"{self.base_url.rstrip('/')}/{self.program_handle}",
            status_code=0,
            metadata={"payload_preview": payload, "dry_run": True},
        )


@dataclass(slots=True)
class BugcrowdTicketCreator(TicketCreatorBase):
    """Skeleton Bugcrowd submission creator."""

    api_token: str = ""
    program_code: str = ""
    base_url: str = "https://api.bugcrowd.com"

    def __post_init__(self) -> None:
        TicketCreatorBase.__post_init__(self)
        self.platform_label = "bugcrowd"

    def _do_create(
        self, finding: Mapping[str, Any], review_brief: str
    ) -> TicketResult:
        if not self.api_token:
            return TicketResult(
                platform="bugcrowd",
                finding_key=self._finding_fingerprint(finding),
                ok=False,
                error="BUGCROWD_API_TOKEN not configured",
            )
        if not self.program_code:
            return TicketResult(
                platform="bugcrowd",
                finding_key=self._finding_fingerprint(finding),
                ok=False,
                error="program_code not configured",
            )
        logger.info(
            "BugcrowdTicketCreator: would POST to %s/submissions for program %s",
            self.base_url,
            self.program_code,
        )
        return TicketResult(
            platform="bugcrowd",
            finding_key=self._finding_fingerprint(finding),
            ok=True,
            url=f"{self.base_url.rstrip('/')}/submissions",
            status_code=0,
            metadata={"dry_run": True},
        )


@dataclass(slots=True)
class JiraTicketCreator(TicketCreatorBase):
    """Skeleton Jira issue creator.

    Uses the Jira Cloud REST API v3 ``POST /rest/api/3/issue`` shape
    with an ADF description.  Real POSTs are out of scope for the
    skeleton — operators wire them in via the standard ``requests``
    library once credentials are provided.
    """

    base_url: str = ""
    project_key: str = ""
    email: str = ""
    api_token: str = ""
    issue_type: str = "Bug"

    def __post_init__(self) -> None:
        TicketCreatorBase.__post_init__(self)
        self.platform_label = "jira"

    def _do_create(
        self, finding: Mapping[str, Any], review_brief: str
    ) -> TicketResult:
        if not self.base_url or not self.project_key:
            return TicketResult(
                platform="jira",
                finding_key=self._finding_fingerprint(finding),
                ok=False,
                error="jira base_url and project_key required",
            )
        if not (self.email and self.api_token):
            return TicketResult(
                platform="jira",
                finding_key=self._finding_fingerprint(finding),
                ok=False,
                error="jira credentials (email + api_token) not configured",
            )
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": str(finding.get("title", "Security finding"))[:240],
                "issuetype": {"name": self.issue_type},
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": review_brief}],
                        }
                    ],
                },
                "labels": [
                    "security",
                    f"severity-{str(finding.get('severity', 'info')).lower()}",
                ],
            }
        }
        logger.info(
            "JiraTicketCreator: would POST to %s/rest/api/3/issue for project %s",
            self.base_url,
            self.project_key,
        )
        return TicketResult(
            platform="jira",
            finding_key=self._finding_fingerprint(finding),
            ok=True,
            url=f"{self.base_url.rstrip('/')}/browse/{self.project_key}-<new>",
            status_code=0,
            metadata={"payload_preview": payload, "dry_run": True},
        )


def _severity_to_hackerone(severity: Any) -> str:
    """Map a pipeline severity string to a Hackerone severity rating."""
    sev = str(severity or "").lower()
    if sev == "critical":
        return "critical"
    if sev == "high":
        return "high"
    if sev == "medium":
        return "medium"
    if sev == "low":
        return "low"
    return "none"


def _creator_from_config_block(
    platform: str, block: Mapping[str, Any]
) -> TicketCreatorBase:
    enabled = bool(block.get("enabled", False))
    min_severity = str(block.get("min_severity", "high"))
    if platform == "hackerone":
        return HackerOneTicketCreator(
            enabled=enabled,
            min_severity=min_severity,
            api_token=str(block.get("api_token") or os.environ.get("HACKERONE_API_TOKEN", "")),
            program_handle=str(block.get("program_handle", "")),
            base_url=str(block.get("base_url", "https://api.hackerone.com")),
        )
    if platform == "bugcrowd":
        return BugcrowdTicketCreator(
            enabled=enabled,
            min_severity=min_severity,
            api_token=str(block.get("api_token") or os.environ.get("BUGCROWD_API_TOKEN", "")),
            program_code=str(block.get("program_code", "")),
            base_url=str(block.get("base_url", "https://api.bugcrowd.com")),
        )
    if platform == "jira":
        return JiraTicketCreator(
            enabled=enabled,
            min_severity=min_severity,
            base_url=str(block.get("base_url", "")),
            project_key=str(block.get("project_key", "")),
            email=str(block.get("email") or os.environ.get("JIRA_EMAIL", "")),
            api_token=str(
                block.get("api_token") or os.environ.get("JIRA_API_TOKEN", "")
            ),
            issue_type=str(block.get("issue_type", "Bug")),
        )
    raise ValueError(f"unknown ticket_creator platform: {platform!r}")


def create_ticket_creators_from_config(
    config: Any,
) -> list[TicketCreatorBase]:
    """Build every ticket creator declared in ``config.ticket_creators``.

    ``config.ticket_creators`` may be a Mapping (e.g. loaded from TOML)
    or an attribute on a dataclass.  Returns an empty list when the
    section is missing or ticket creation is disabled.
    """
    section: Any = None
    if config is None:
        return []
    if isinstance(config, Mapping):
        section = config.get("ticket_creators")
    else:
        section = getattr(config, "ticket_creators", None)

    if not section:
        return []

    if isinstance(section, Mapping):
        if not bool(section.get("enabled", False)):
            return []
        blocks: Iterable[tuple[str, Mapping[str, Any]]] = (
            (platform, dict(values or {}))
            for platform, values in section.items()
            if platform != "enabled" and isinstance(values, Mapping)
        )
    else:
        try:
            if not bool(getattr(section, "enabled", False)):
                return []
        except AttributeError:
            return []
        blocks = []
        for platform in ("hackerone", "bugcrowd", "jira"):
            block = getattr(section, platform, None)
            if block is not None and isinstance(block, Mapping):
                blocks.append((platform, dict(block)))

    creators: list[TicketCreatorBase] = []
    for platform, block in blocks:
        try:
            creators.append(_creator_from_config_block(platform, block))
        except ValueError as exc:
            logger.warning("Skipping ticket creator %s: %s", platform, exc)
    return creators


def register_default_ticket_creators() -> None:
    """Register no-op creators with the plugin registry.

    Real creators are config-driven; the registry exists so the
    reporting stage can look up ``resolve_plugin(TICKET_CREATOR, key)``
    without crashing when no creator has been configured yet.  This
    registration only seeds the registry slot — operators instantiate
    :class:`JiraTicketCreator` (or HackerOne/Bugcrowd) with concrete
    settings and call :func:`create_ticket_creators_from_config` to
    wire them up.
    """
    register_plugin(TICKET_CREATOR, "hackerone")(HackerOneTicketCreator)
    register_plugin(TICKET_CREATOR, "bugcrowd")(BugcrowdTicketCreator)
    register_plugin(TICKET_CREATOR, "jira")(JiraTicketCreator)


__all__ = [
    "TICKET_CREATOR",
    "BugcrowdTicketCreator",
    "HackerOneTicketCreator",
    "JiraTicketCreator",
    "TicketCreatorBase",
    "TicketResult",
    "create_ticket_creators_from_config",
    "register_default_ticket_creators",
]
