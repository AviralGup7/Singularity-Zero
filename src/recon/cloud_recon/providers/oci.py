"""Oracle Cloud Infrastructure Object Storage checks."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

from src.recon.cloud_recon.constants import _OCI_REGIONS

logger = logging.getLogger(__name__)


async def probe_oci_object_storage(
    session: aiohttp.ClientSession,
    project_id: str,
    *,
    timeout_seconds: int = 5,
    oci_regions: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    regions = oci_regions or _OCI_REGIONS
    bucket_candidates = [
        project_id,
        f"{project_id}-backup",
        f"{project_id}-assets",
        "bucket",
    ]
    for region in regions:
        for bucket_name in bucket_candidates:
            url = f"https://{bucket_name}.objectstorage.{region}.oraclecloud.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 301, 302, 403):
                        findings.append(
                            {
                                "platform": "OCI Object Storage",
                                "bucket": bucket_name,
                                "url": url,
                                "region": region,
                                "status": "detected",
                                "severity": "info",
                                "details": (
                                    f"OCI Object Storage URL responded with HTTP {resp.status}."
                                ),
                            }
                        )
            except Exception:
                logger.debug("OCI Object Storage probe failed for %s", url)
                continue
    return findings
