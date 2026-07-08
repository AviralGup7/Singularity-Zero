"""DigitalOcean Spaces checks."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

from src.recon.cloud_recon.constants import _DO_REGIONS

logger = logging.getLogger(__name__)


async def probe_digitalocean_spaces(
    session: aiohttp.ClientSession,
    project_id: str,
    *,
    timeout_seconds: int = 5,
    do_regions: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    regions = do_regions or _DO_REGIONS
    space_candidates = [
        project_id,
        f"{project_id}-assets",
        f"{project_id}-files",
        f"{project_id}-backup",
        "space",
    ]
    for region in regions:
        for space_name in space_candidates:
            url = f"https://{space_name}.{region}.digitaloceanspaces.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 301, 302, 403):
                        findings.append(
                            {
                                "platform": "DigitalOcean Spaces",
                                "space_name": space_name,
                                "url": url,
                                "region": region,
                                "status": "detected",
                                "severity": "info",
                                "details": (
                                    f"DigitalOcean Space URL responded with HTTP {resp.status}."
                                ),
                            }
                        )
            except Exception:
                logger.debug("DigitalOcean Spaces probe failed for %s", url)
                continue
    return findings
