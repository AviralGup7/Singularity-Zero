"""GCP Cloud Storage, Cloud Functions, and App Engine checks."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)


async def check_gcp_bucket(
    session: aiohttp.ClientSession,
    bucket: str,
    *,
    timeout_seconds: int = 5,
    enable_write_probes: bool = False,
) -> dict[str, Any] | None:
    """Check Google Cloud Storage bucket status and permissions."""
    url = f"https://storage.googleapis.com/{bucket}"
    try:
        finding: dict[str, Any] | None = None
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout_seconds)
        ) as response:
            status = response.status
            if status == 200:
                finding = {
                    "platform": "GCP Cloud Storage",
                    "bucket": bucket,
                    "url": url,
                    "status": "public",
                    "severity": "high",
                    "details": "Publicly indexable / directory listing enabled.",
                    "permissions": {"read": True},
                }
            elif status == 403:
                finding = {
                    "platform": "GCP Cloud Storage",
                    "bucket": bucket,
                    "url": url,
                    "status": "secure",
                    "severity": "info",
                    "details": "Bucket exists, but access is restricted (403 Forbidden).",
                    "permissions": {"read": False},
                }

        if finding:
            try:
                async with session.get(
                    f"{url}?acl", timeout=aiohttp.ClientTimeout(total=timeout_seconds)
                ) as acl_resp:
                    finding["permissions"]["read_acl"] = acl_resp.status == 200
                    if acl_resp.status == 200:
                        finding["severity"] = "high"
                        finding["details"] += " ACL is publicly readable."
            except Exception:
                logger.warning("Operation failed in gcp.py", exc_info=True)
            if enable_write_probes:
                try:
                    async with session.put(
                        f"{url}/cyber_pipeline_write_test.txt",
                        data="test",
                        timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                    ) as put_resp:
                        finding["permissions"]["write"] = put_resp.status == 200
                        if put_resp.status == 200:
                            finding["severity"] = "critical"
                            finding["details"] += (
                                " Bucket allows unauthenticated file uploads (Public Write)!"
                            )
                except Exception:
                    logger.warning("Operation failed in gcp.py", exc_info=True)
            return finding

    except Exception:
        logger.warning("Operation failed in gcp.py", exc_info=True)
    return None


async def probe_gcp_cloud_functions(
    session: aiohttp.ClientSession,
    project_id: str,
    *,
    timeout_seconds: int = 5,
    gcp_regions: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    from src.recon.cloud_recon.constants import _DEFAULT_GCP_REGIONS

    findings: list[dict[str, Any]] = []
    regions = gcp_regions or _DEFAULT_GCP_REGIONS
    for region in regions:
        base = f"https://{region}-{project_id}.cloudfunctions.net"
        for function_name in [
            project_id,
            f"{project_id}-api",
            f"{project_id}-service",
            f"{project_id}-app",
            "api",
            "service",
            "web",
        ]:
            url = f"{base}/{function_name}"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 301, 302, 401, 403):
                        findings.append(
                            {
                                "platform": "GCP Cloud Functions",
                                "service": function_name,
                                "url": url,
                                "region": region,
                                "status": "detected",
                                "severity": "info",
                                "details": (
                                    f"Cloud Function URL responded with HTTP {resp.status}."
                                ),
                            }
                        )
            except Exception:
                logger.debug("GCP Cloud Function probe failed for %s", url)
                continue
    second_gen_base = f"https://{project_id}-{regions[0]}.cloudfunctions.net"
    try:
        async with session.get(
            second_gen_base,
            timeout=aiohttp.ClientTimeout(total=timeout_seconds),
            allow_redirects=False,
        ) as resp:
            if resp.status in (200, 301, 302, 401, 403):
                findings.append(
                    {
                        "platform": "GCP Cloud Functions (2nd Gen)",
                        "url": second_gen_base,
                        "region": regions[0],
                        "status": "detected",
                        "severity": "info",
                        "details": (
                            f"2nd Gen Cloud Functions base URL responded with HTTP {resp.status}."
                        ),
                    }
                )
    except Exception:
        logger.warning("Operation failed in gcp.py", exc_info=True)
    return findings


async def probe_gcp_app_engine(
    session: aiohttp.ClientSession,
    project_id: str,
    *,
    timeout_seconds: int = 5,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    candidates = [
        f"https://{project_id}.appspot.com",
        f"https://{project_id}.uc.r.appspot.com",
        f"https://{project_id}.ew.r.appspot.com",
        f"https://{project_id}.ae.r.appspot.com",
    ]
    for version in ["v1", "prod", "staging", "dev", "default"]:
        candidates.append(f"https://{version}-dot-{project_id}.appspot.com")
    for url in candidates:
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                allow_redirects=False,
            ) as resp:
                if resp.status in (200, 301, 302):
                    findings.append(
                        {
                            "platform": "GCP App Engine",
                            "url": url,
                            "status": "public",
                            "severity": "info",
                            "details": (f"App Engine URL responded with HTTP {resp.status}."),
                        }
                    )
        except Exception:
            logger.debug("GCP App Engine probe failed for %s", url)
            continue
    return findings
