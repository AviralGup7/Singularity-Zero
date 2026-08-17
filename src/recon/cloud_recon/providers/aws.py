"""AWS S3 bucket and service checks."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

from src.recon.cloud_recon.constants import (
    _S3_COMMON_OBJECT_PATHS,
    DEFAULT_S3_WEBSITE_REGIONS,
)

logger = logging.getLogger(__name__)


async def check_aws_bucket(
    session: aiohttp.ClientSession,
    bucket: str,
    *,
    timeout_seconds: int = 5,
    enable_write_probes: bool = False,
    s3_website_regions: tuple[str, ...] | None = None,
    s3_object_paths: tuple[str, ...] | None = None,
) -> dict[str, Any] | None:
    """Check AWS S3 bucket status and permissions."""
    url = f"https://{bucket}.s3.amazonaws.com"
    try:
        finding: dict[str, Any] | None = None
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout_seconds)
        ) as response:
            status = response.status
            if status == 200:
                finding = {
                    "platform": "AWS S3",
                    "bucket": bucket,
                    "url": url,
                    "status": "public",
                    "severity": "high",
                    "details": "Publicly indexable / directory listing enabled.",
                    "permissions": {"read": True},
                }
            elif status == 403:
                finding = {
                    "platform": "AWS S3",
                    "bucket": bucket,
                    "url": url,
                    "status": "secure",
                    "severity": "info",
                    "details": "Bucket exists, but access is restricted (403 Forbidden).",
                    "permissions": {"read": False},
                }
            else:
                return None

        if finding:
            try:
                async with session.get(
                    f"{url}/?acl", timeout=aiohttp.ClientTimeout(total=timeout_seconds)
                ) as acl_resp:
                    finding["permissions"]["read_acl"] = acl_resp.status == 200
                    if acl_resp.status == 200:
                        finding["severity"] = "high"
                        finding["details"] += " ACL is publicly readable."
            except Exception:
                logger.warning("Operation failed in aws.py", exc_info=True)
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
                    logger.warning("Operation failed in aws.py", exc_info=True)
            website_findings = await _probe_s3_website(
                session,
                bucket,
                timeout_seconds=timeout_seconds,
                s3_website_regions=s3_website_regions,
            )
            if website_findings:
                finding["permissions"]["static_website"] = True
                finding["severity"] = "high"
                finding["details"] += (
                    f" Static-website endpoint(s) public: {', '.join(website_findings)}."
                )

            public_objects = await _probe_common_object_paths(
                session,
                url,
                timeout_seconds=timeout_seconds,
                s3_object_paths=s3_object_paths,
            )
            if public_objects:
                finding["permissions"]["public_objects"] = public_objects
                finding["severity"] = "high"
                finding["details"] += f" Publicly readable object(s): {', '.join(public_objects)}."

            try:
                async with session.get(
                    f"{url}/?policy",
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                ) as policy_resp:
                    if policy_resp.status == 200:
                        finding["permissions"]["public_policy"] = True
                        if finding["severity"] not in ("high", "critical"):
                            finding["severity"] = "medium"
                        finding["details"] += " Bucket policy document is publicly readable."
            except Exception:
                logger.warning("Operation failed in aws.py", exc_info=True)
            return finding

    except Exception:
        logger.warning("Operation failed in aws.py", exc_info=True)
    return None


async def _probe_s3_website(
    session: aiohttp.ClientSession,
    bucket: str,
    *,
    timeout_seconds: int = 5,
    s3_website_regions: tuple[str, ...] | None = None,
) -> list[str]:
    """Probe the S3 static-website hosting endpoint for each configured region."""
    public_regions: list[str] = []
    regions = s3_website_regions or DEFAULT_S3_WEBSITE_REGIONS
    for region in regions:
        url = f"http://{bucket}.s3-website-{region}.amazonaws.com"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                allow_redirects=True,
            ) as resp:
                if resp.status in (200, 301, 302):
                    public_regions.append(region)
        except Exception:
            logger.debug("S3 website probe failed for %s", url)
            continue
    return public_regions


async def _probe_common_object_paths(
    session: aiohttp.ClientSession,
    bucket_url: str,
    *,
    timeout_seconds: int = 5,
    s3_object_paths: tuple[str, ...] | None = None,
) -> list[str]:
    """Probe each path in ``s3_object_paths`` for a 200 response."""
    public_paths: list[str] = []
    paths = s3_object_paths or _S3_COMMON_OBJECT_PATHS
    for path in paths:
        url = f"{bucket_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with session.head(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    public_paths.append(path)
        except Exception:
            logger.debug("Common object path probe failed for %s", url)
            continue
    return public_paths


async def probe_aws_lambda_urls(
    session: aiohttp.ClientSession,
    project_id: str,
    *,
    timeout_seconds: int = 5,
    aws_regions: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    from src.recon.cloud_recon.constants import _DEFAULT_AWS_REGIONS

    findings: list[dict[str, Any]] = []
    regions = aws_regions or _DEFAULT_AWS_REGIONS
    function_candidates = [
        project_id,
        f"{project_id}-function",
        f"{project_id}-api",
        f"{project_id}-handler",
        "api",
        "handler",
        "webhook",
    ]
    for region in regions:
        for func_name in function_candidates:
            url = f"https://{func_name}.lambda-url.{region}.on.aws"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 301, 302, 401, 403):
                        findings.append(
                            {
                                "platform": "AWS Lambda Function URL",
                                "function_name": func_name,
                                "url": url,
                                "region": region,
                                "status": "detected",
                                "severity": "info",
                                "details": (
                                    f"Lambda Function URL responded with HTTP {resp.status}."
                                ),
                            }
                        )
            except Exception:
                logger.debug("AWS Lambda URL probe failed for %s", url)
                continue
    return findings


async def probe_api_gateway(
    session: aiohttp.ClientSession,
    project_id: str,
    *,
    timeout_seconds: int = 5,
    aws_regions: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    from src.recon.cloud_recon.constants import _DEFAULT_AWS_REGIONS

    findings: list[dict[str, Any]] = []
    regions = aws_regions or _DEFAULT_AWS_REGIONS
    api_candidates = [
        project_id,
        f"{project_id}-api",
        f"{project_id}-gw",
        f"{project_id}-gateway",
        "api",
        "gateway",
    ]
    for region in regions:
        for api_id in api_candidates:
            urls = [
                f"https://{api_id}.execute-api.{region}.amazonaws.com",
                f"https://{api_id}.execute-api.{region}.vpce.amazonaws.com",
            ]
            for url in urls:
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (200, 301, 302, 401, 403):
                            findings.append(
                                {
                                    "platform": "AWS API Gateway",
                                    "api_id": api_id,
                                    "url": url,
                                    "region": region,
                                    "status": "detected",
                                    "severity": "info",
                                    "details": (
                                        f"API Gateway endpoint responded with HTTP {resp.status}."
                                    ),
                                }
                            )
                except Exception:
                    logger.debug("API Gateway probe failed for %s", url)
                    continue
    return findings


async def probe_aws_amplify(
    session: aiohttp.ClientSession,
    project_id: str,
    *,
    timeout_seconds: int = 5,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    app_id_candidates = [project_id, f"{project_id}1234567890"]
    branch_candidates = [
        "main",
        "master",
        "prod",
        "staging",
        "dev",
        "preview",
        "develop",
        "production",
    ]
    for app_id in app_id_candidates:
        for branch in branch_candidates:
            url = f"https://{branch}.{app_id}.amplifyapp.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 301, 302):
                        findings.append(
                            {
                                "platform": "AWS Amplify",
                                "app_id": app_id,
                                "branch": branch,
                                "url": url,
                                "status": "public",
                                "severity": "info",
                                "details": (
                                    f"Amplify branch URL responded with HTTP {resp.status}."
                                ),
                            }
                        )
            except Exception:
                logger.debug("AWS Amplify probe failed for %s", url)
                continue
    return findings


async def probe_s3_access_points(
    session: aiohttp.ClientSession,
    base_name: str,
    *,
    timeout_seconds: int = 5,
    aws_regions: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    from src.recon.cloud_recon.constants import _DEFAULT_AWS_REGIONS

    findings: list[dict[str, Any]] = []
    regions = aws_regions or _DEFAULT_AWS_REGIONS
    access_point_candidates = [
        base_name,
        f"{base_name}-ap",
        f"{base_name}-access",
        f"{base_name}-edge",
        "access",
        "edge",
    ]
    for ap_name in access_point_candidates:
        for region in regions:
            url = f"https://{ap_name}-<account-id>.s3-accesspoint.{region}.amazonaws.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (403, 200):
                        findings.append(
                            {
                                "platform": "AWS S3 Access Point",
                                "access_point_name": ap_name,
                                "url": url.replace("<account-id>", "<unverified>"),
                                "region": region,
                                "status": "detected",
                                "severity": "info",
                                "details": (f"S3 Access Point responded with HTTP {resp.status}."),
                            }
                        )
            except Exception:
                logger.debug("S3 Access Point probe failed for %s", url)
                continue
    return findings


async def probe_multi_region_s3(
    session: aiohttp.ClientSession,
    bucket: str,
    *,
    timeout_seconds: int = 5,
    aws_regions: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    from src.recon.cloud_recon.constants import _DEFAULT_AWS_REGIONS

    findings: list[dict[str, Any]] = []
    regions = aws_regions or _DEFAULT_AWS_REGIONS
    path_style_urls = [f"https://s3.{region}.amazonaws.com/{bucket}" for region in regions]
    vhost_style_urls = [f"https://{bucket}.s3.{region}.amazonaws.com" for region in regions]
    urls = path_style_urls + vhost_style_urls
    for url in urls:
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                allow_redirects=False,
            ) as resp:
                if resp.status in (200, 301, 302, 403):
                    findings.append(
                        {
                            "platform": "AWS S3 Multi-Region",
                            "bucket": bucket,
                            "url": url,
                            "region": _extract_region_from_url(url),
                            "status": "detected",
                            "severity": "info",
                            "details": (f"S3 endpoint responded with HTTP {resp.status}."),
                        }
                    )
        except Exception:
            logger.debug("Multi-region S3 probe failed for %s", url)
            continue
    return findings


def _extract_region_from_url(url: str) -> str:
    try:
        parts = url.split(".amazonaws.com")
        if parts:
            prefix = parts[0]
            region_candidate = prefix.split(".")[-2]
            if region_candidate not in {"s3", "execute-api", "vpce", "lambda-url"}:
                return region_candidate
    except Exception:
        logger.warning("Operation failed in aws.py", exc_info=True)
    return "unknown"
