from __future__ import annotations

import logging
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)


async def _probe_s3_website(
    scanner: Any,
    session: aiohttp.ClientSession,
    bucket: str,
) -> list[str]:
    public_regions: list[str] = []
    for region in getattr(scanner, "s3_website_regions", ()):
        url = f"http://{bucket}.s3-website-{region}.amazonaws.com"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=getattr(scanner, "timeout_seconds", 5)),
                allow_redirects=True,
            ) as resp:
                if resp.status in (200, 301, 302):
                    public_regions.append(region)
        except Exception:
            logger.debug("S3 website probe failed for %s", url)
            continue
    return public_regions


async def _probe_common_object_paths(
    scanner: Any,
    session: aiohttp.ClientSession,
    bucket_url: str,
) -> list[str]:
    public_paths: list[str] = []
    for path in getattr(scanner, "s3_object_paths", ()):
        url = f"{bucket_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with session.head(
                url,
                timeout=aiohttp.ClientTimeout(total=getattr(scanner, "timeout_seconds", 5)),
                allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    public_paths.append(path)
        except Exception:
            logger.debug("Common object path probe failed for %s", url)
            continue
    return public_paths


async def _generic_object_storage_check(
    scanner: Any,
    session: aiohttp.ClientSession,
    *,
    bucket: str,
    url: str,
    platform: str,
    extra_endpoints: list[str] | None = None,
) -> dict[str, Any] | None:
    urls_to_try = [url]
    if extra_endpoints:
        urls_to_try.extend(extra_endpoints)
    for candidate_url in urls_to_try:
        try:
            async with session.get(
                candidate_url,
                timeout=aiohttp.ClientTimeout(total=getattr(scanner, "timeout_seconds", 5)),
            ) as response:
                status = response.status
                if status == 200:
                    return {
                        "platform": platform,
                        "bucket": bucket,
                        "url": candidate_url,
                        "status": "public",
                        "severity": "high",
                        "details": "Bucket is publicly indexable.",
                        "permissions": {"read": True},
                    }
                if status == 403:
                    return {
                        "platform": platform,
                        "bucket": bucket,
                        "url": candidate_url,
                        "status": "secure",
                        "severity": "info",
                        "details": "Bucket exists; access is restricted.",
                        "permissions": {"read": False},
                    }
        except Exception:
            pass
    return None
