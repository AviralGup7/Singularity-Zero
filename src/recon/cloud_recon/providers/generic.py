"""Generic S3-compatible object storage checks (Alibaba, Tencent)."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)


async def _generic_object_storage_check(
    session: aiohttp.ClientSession,
    *,
    bucket: str,
    url: str,
    platform: str,
    timeout_seconds: int = 5,
    extra_endpoints: list[str] | None = None,
) -> dict[str, Any] | None:
    """Shared implementation for S3-compatible object stores."""
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout_seconds)
        ) as response:
            status = response.status
            if status == 200:
                return {
                    "platform": platform,
                    "bucket": bucket,
                    "url": url,
                    "status": "public",
                    "severity": "high",
                    "details": "Bucket is publicly indexable.",
                    "permissions": {"read": True},
                }
            if status == 403:
                return {
                    "platform": platform,
                    "bucket": bucket,
                    "url": url,
                    "status": "secure",
                    "severity": "info",
                    "details": "Bucket exists; access is restricted.",
                    "permissions": {"read": False},
                }
    except Exception:
        logger.warning("Operation failed in generic.py", exc_info=True)
    return None


async def check_alibaba_bucket(
    session: aiohttp.ClientSession,
    bucket: str,
    *,
    timeout_seconds: int = 5,
) -> dict[str, Any] | None:
    """Check Alibaba Cloud OSS bucket status."""
    url = f"https://{bucket}.oss-cn-hangzhou.aliyuncs.com"
    return await _generic_object_storage_check(
        session,
        bucket=bucket,
        url=url,
        platform="Alibaba OSS",
        timeout_seconds=timeout_seconds,
        extra_endpoints=[
            f"https://{bucket}.oss.aliyuncs.com",
        ],
    )


async def check_tencent_bucket(
    session: aiohttp.ClientSession,
    bucket: str,
    *,
    timeout_seconds: int = 5,
) -> dict[str, Any] | None:
    """Check Tencent Cloud COS bucket status."""
    url = f"https://{bucket}.cos.ap-guangzhou.myqcloud.com"
    return await _generic_object_storage_check(
        session,
        bucket=bucket,
        url=url,
        platform="Tencent COS",
        timeout_seconds=timeout_seconds,
    )
