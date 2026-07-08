"""Firebase Hosting checks."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)


async def probe_firebase_hosting(
    session: aiohttp.ClientSession,
    project_id: str,
    *,
    timeout_seconds: int = 5,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    channel_candidates = [
        "live",
        "preview",
        "prod",
        "staging",
        "dev",
        "production",
    ]
    for channel in channel_candidates:
        for domain_suffix in ["web.app", "firebaseapp.com"]:
            url = f"https://{channel}.{project_id}.{domain_suffix}"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 301, 302):
                        findings.append(
                            {
                                "platform": "Firebase Hosting",
                                "url": url,
                                "channel": channel,
                                "status": "public",
                                "severity": "info",
                                "details": (
                                    f"Firebase Hosting URL responded with HTTP {resp.status}."
                                ),
                            }
                        )
            except Exception:
                logger.debug("Firebase Hosting probe failed for %s", url)
                continue
    return findings
