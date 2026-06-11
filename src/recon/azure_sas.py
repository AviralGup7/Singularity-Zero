"""Azure Storage SAS enumeration helpers.

The previous :mod:`src.recon.cloud_recon` module only checks the
Azure Storage REST API endpoint (returning 400/403 for "the account
exists, you just can't list it"). Modern Azure recon also needs
to enumerate the two most commonly-misconfigured Azure surfaces:

1. **The ``$web`` static-website container.** When the static-website
   feature is enabled, ``https://<account>.z6.web.core.windows.net``
   serves a public listing of the ``$web`` container. The previous
   code did not probe this.
2. **The ``?restype=container&comp=list`` listing endpoint.** A
   public container with anonymous listing enabled returns 200 with
   an XML blob listing. This is reachable even when the
   ``$web`` endpoint is not configured.

This module also implements **SAS pattern generation** — given an
Azure storage account name and a known container name, we generate
candidate SAS URLs the operator can attempt with **read-only**
``sp=rl`` permissions. We do not actually request the SAS tokens
(the SAS signing key is per-account and is never exposed without
authentication), but the generated patterns are useful for
hand-driven test plans.

Note: We do NOT attempt to brute-force SAS signatures. Brute-forcing
SHA-256 HMACs is computationally infeasible, and any tool that
claims to do so is at best snake-oil.
"""

from __future__ import annotations

import datetime as _dt
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, cast
from urllib.parse import quote, urlencode

import aiohttp

logger = logging.getLogger(__name__)

# Azure Storage endpoint conventions. ``z6.web.core.windows.net`` is
# the standard static-website hostname; the numeric segment rotates
# (``z6``, ``z7``, ...) but ``z6`` is the most common default.
_AZURE_WEB_ENDPOINT_FAMILY = "z6.web.core.windows.net"
_AZURE_BLOB_ENDPOINT_FAMILY = "blob.core.windows.net"
_AZURE_FILE_ENDPOINT_FAMILY = "file.core.windows.net"
_AZURE_QUEUE_ENDPOINT_FAMILY = "queue.core.windows.net"

# Valid characters for Azure storage account names: lowercase
# letters + digits, length 3-24.
_AZURE_NAME_RE = re.compile(r"^[a-z0-9]{3,24}$")

# Common container names to enumerate. These follow the same
# suffix-based pattern as S3 bucket candidates but with Azure's
# underscore-hyphen rules.
_AZURE_COMMON_CONTAINERS: tuple[str, ...] = (
    "$web",
    "$logs",
    "backup",
    "backups",
    "data",
    "files",
    "public",
    "assets",
    "static",
    "media",
    "uploads",
    "downloads",
    "archive",
    "logs",
    "test",
    "dev",
    "prod",
    "staging",
    "internal",
    "shared",
    "default",
)

# Permission strings for the ``sp=`` SAS parameter. The list is
# deliberately conservative (read-only and read-list) — we never
# suggest write or delete permissions in a generated test URL.
_READ_PERMS: tuple[str, ...] = ("r", "rl")


# ---------------------------------------------------------------------------
# Public data class
# ---------------------------------------------------------------------------


@dataclass
class AzureSasUrlPattern:
    """A SAS URL pattern (no signature) for a container / blob combination."""

    account: str
    container: str
    blob: str | None
    permissions: str
    expiry: str
    url: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "account": self.account,
            "container": self.container,
            "blob": self.blob,
            "permissions": self.permissions,
            "expiry": self.expiry,
            "url": self.url,
        }


@dataclass
class AzureReconResult:
    """Aggregated Azure storage recon result for a target."""

    target: str = ""
    account_candidates: list[str] = field(default_factory=list)
    public_web_findings: list[dict[str, Any]] = field(default_factory=list)
    public_listing_findings: list[dict[str, Any]] = field(default_factory=list)
    sas_patterns: list[AzureSasUrlPattern] = field(default_factory=list)
    errors: int = 0
    web_endpoints: list[str] = field(default_factory=list)
    listing_endpoints: list[str] = field(default_factory=list)

    def _normalize_web_findings(self) -> None:
        self.web_endpoints = [
            f if isinstance(f, str) else f.get("url", str(f)) for f in self.public_web_findings
        ]
        self.listing_endpoints = [
            f if isinstance(f, str) else f.get("url", str(f)) for f in self.public_listing_findings
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_candidates": list(self.account_candidates),
            "public_web_count": len(self.public_web_findings),
            "public_listing_count": len(self.public_listing_findings),
            "sas_pattern_count": len(self.sas_patterns),
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Account candidate generation
# ---------------------------------------------------------------------------


def azure_account_candidates(target: str) -> list[str]:
    """Generate Azure storage account name candidates from a target brand.

    Args:
        target: Domain or brand (e.g. ``example.com``).

    Returns:
        List of unique account name candidates (3-24 chars,
        lowercase alphanumeric).
    """
    from urllib.parse import urlparse

    parsed = urlparse(target if "://" in target else f"https://{target}")
    domain = parsed.hostname or parsed.path or target
    core_name = domain.split(".")[0].lower().strip()
    if not core_name:
        return []

    # Azure allows lowercase alphanumeric only; the core name might
    # contain dashes which we strip.
    sanitized = re.sub(r"[^a-z0-9]", "", core_name)
    if not (3 <= len(sanitized) <= 24):
        # Truncate to the maximum allowed length
        sanitized = sanitized[:24]
        if len(sanitized) < 3:
            return []

    suffixes = (
        "prod",
        "dev",
        "test",
        "stage",
        "staging",
        "data",
        "backup",
        "files",
        "media",
        "static",
        "assets",
        "public",
        "logs",
    )
    candidates: set[str] = set()
    candidates.add(sanitized)
    for suffix in suffixes:
        candidate = f"{sanitized}{suffix}"
        if 3 <= len(candidate) <= 24:
            candidates.add(candidate)
    return sorted(c for c in candidates if _AZURE_NAME_RE.match(c))


# ---------------------------------------------------------------------------
# Live probing
# ---------------------------------------------------------------------------


def _normalize_endpoint(account: str, family: str) -> str:
    return f"https://{account}.{family}"


async def _check_azure_web(session: aiohttp.ClientSession, account: str) -> dict[str, Any] | None:
    """Check ``<account>.z6.web.core.windows.net`` for static-website hosting."""
    url = _normalize_endpoint(account, _AZURE_WEB_ENDPOINT_FAMILY)
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=5),
            allow_redirects=True,
        ) as resp:
            if resp.status == 200:
                body = await resp.text()
                return {
                    "platform": "Azure Static Website",
                    "account": account,
                    "url": url,
                    "status": "public",
                    "severity": "high",
                    "details": "Static website container is publicly indexable.",
                    "permissions": {"read": True},
                    "content_length": len(body),
                }
            if resp.status == 404:
                # The account exists but the $web container is empty
                # or the feature is not enabled. This is not a finding.
                return {
                    "platform": "Azure Static Website",
                    "account": account,
                    "url": url,
                    "status": "absent",
                    "severity": "info",
                    "details": "Static website is not configured on this account.",
                }
    except (TimeoutError, aiohttp.ClientError) as exc:
        logger.debug("Azure web probe failed for %s: %s", account, exc)
    return None


async def _check_azure_listing(
    session: aiohttp.ClientSession,
    account: str,
    container: str,
) -> dict[str, Any] | None:
    """Check ``?restype=container&comp=list`` for a public container."""
    url = (
        _normalize_endpoint(account, _AZURE_BLOB_ENDPOINT_FAMILY)
        + f"/{quote(container, safe='$')}?restype=container&comp=list"
    )
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            if resp.status == 200:
                return {
                    "platform": "Azure Blob Container",
                    "account": account,
                    "container": container,
                    "url": url,
                    "status": "public",
                    "severity": "high",
                    "details": "Container is publicly listable without authentication.",
                    "permissions": {"read": True, "list": True},
                }
    except (TimeoutError, aiohttp.ClientError) as exc:
        logger.debug("Azure listing probe failed for %s/%s: %s", account, container, exc)
    return None


# ---------------------------------------------------------------------------
# SAS pattern generation
# ---------------------------------------------------------------------------


def _generate_sas_patterns(
    account: str,
    container: str,
    blob: str | None = None,
    *,
    expiry_hours: int = 24,
) -> list[AzureSasUrlPattern]:
    """Build read-only SAS URL patterns for testing.

    The signatures in these patterns are placeholders (``<sig>``).
    Operators that want to attempt an actual signed URL must obtain
    a valid signature out-of-band (e.g. via the storage account
    owner or a leaked ``SharedAccessSignature`` query string).

    Args:
        account: Azure storage account name.
        container: Container name.
        blob: Optional blob path inside the container.
        expiry_hours: Hours from now until the SAS expires.

    Returns:
        List of :class:`AzureSasUrlPattern` records.
    """
    if not (_AZURE_NAME_RE.match(account) and container):
        return []
    expiry_dt = _dt.datetime.now(_dt.UTC) + _dt.timedelta(hours=expiry_hours)
    expiry_str = expiry_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    base_path = f"/{account}/{quote(container, safe='$')}"
    if blob:
        base_path += f"/{quote(blob, safe='/')}"
    patterns: list[AzureSasUrlPattern] = []
    for perm in _READ_PERMS:
        params = {
            "sv": "2022-11-02",  # a recent stable API version
            "ss": "b",  # blob service
            "srt": "o",  # resource type: object
            "sp": perm,
            "se": expiry_str,
            "st": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "spr": "https,http",
            "sig": "<sig>",  # placeholder; operators must replace
        }
        url = f"https://{account}.{_AZURE_BLOB_ENDPOINT_FAMILY}{base_path}?{urlencode(params)}"
        patterns.append(
            AzureSasUrlPattern(
                account=account,
                container=container,
                blob=blob,
                permissions=perm,
                expiry=expiry_str,
                url=url,
            )
        )
    return patterns


def generate_sas_patterns_for_account(
    account: str,
    *,
    containers: Iterable[str] | None = None,
    expiry_hours: int = 24,
) -> list[AzureSasUrlPattern]:
    """Generate SAS URL patterns for the most common containers of *account*.

    Args:
        account: Azure storage account name.
        containers: Override the container list.
        expiry_hours: Hours from now until expiry.

    Returns:
        List of patterns. The signatures are placeholders; do not
        attempt to use them in production.
    """
    container_list = list(containers) if containers is not None else list(_AZURE_COMMON_CONTAINERS)
    patterns: list[AzureSasUrlPattern] = []
    for container in container_list:
        patterns.extend(
            _generate_sas_patterns(
                account,
                container,
                blob=None,
                expiry_hours=expiry_hours,
            )
        )
    return patterns


# ---------------------------------------------------------------------------
# End-to-end driver
# ---------------------------------------------------------------------------


# Local import to keep the asyncio symbol available in this module
import asyncio  # noqa: E402


async def scan_azure_accounts(
    target: str,
    *,
    enable_web: bool = True,
    enable_listing: bool = True,
    generate_sas_patterns: bool = True,
    timeout_seconds: int = 30,
    max_workers: int = 4,
) -> AzureReconResult:
    """Top-level Azure recon for a target brand.

    Args:
        target: Brand or domain to derive account candidates from.
        enable_web: Probe the static-website endpoint.
        enable_listing: Probe the ``?comp=list`` listing endpoint.
        generate_sas_patterns: Emit SAS URL patterns for hand testing.
        timeout_seconds: Per-probe timeout.
        max_workers: Max concurrent probes.

    Returns:
        Populated :class:`AzureReconResult`.
    """
    result = AzureReconResult()
    accounts = azure_account_candidates(target)
    result.account_candidates = list(accounts)
    if not accounts:
        return result

    sem = asyncio.Semaphore(max(1, max_workers))
    connector = aiohttp.TCPConnector(limit=max(1, max_workers), ssl=True)

    async def _run_one(account: str) -> None:
        async with sem:
            async with aiohttp.ClientSession(connector=connector) as session:
                if enable_web:
                    web = await _check_azure_web(session, account)
                    if web is not None and web.get("status") == "public":
                        result.public_web_findings.append(web)
                if enable_listing:
                    for container in _AZURE_COMMON_CONTAINERS:
                        listing = await _check_azure_listing(session, account, container)
                        if listing is not None:
                            result.public_listing_findings.append(listing)

    await asyncio.gather(*(_run_one(a) for a in accounts), return_exceptions=True)

    if generate_sas_patterns:
        for account in accounts:
            result.sas_patterns.extend(generate_sas_patterns_for_account(account))

    result.web_endpoints = [
        f.get("url", str(f)) if isinstance(f, dict) else str(f) for f in result.public_web_findings
    ]
    result.listing_endpoints = [
        f.get("url", str(f)) if isinstance(f, dict) else str(f)
        for f in result.public_listing_findings
    ]

    return result


def run_azure_recon_sync(target: str, **kwargs: Any) -> AzureReconResult:
    """Synchronous wrapper around :func:`scan_azure_accounts`."""
    from src.recon.common import run_async_in_sync_context

    return cast(AzureReconResult, run_async_in_sync_context(scan_azure_accounts(target, **kwargs)))


__all__ = [
    "AzureReconResult",
    "AzureSasUrlPattern",
    "azure_account_candidates",
    "generate_sas_patterns_for_account",
    "run_azure_recon_sync",
    "scan_azure_accounts",
]
