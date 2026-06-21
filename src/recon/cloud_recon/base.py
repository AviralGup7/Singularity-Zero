from __future__ import annotations

import asyncio
import logging
from typing import Any, cast
from urllib.parse import urlparse

import aiohttp

from src.recon.cloud_recon.constants import (
    _AZURE_FUNCTIONS_REGIONS,
    _BACKBLAZE_REGIONS,
    _DEFAULT_AWS_REGIONS,
    _DEFAULT_GCP_REGIONS,
    _DO_REGIONS,
    _OCI_REGIONS,
    _S3_COMMON_OBJECT_PATHS,
    _WASABI_REGIONS,
    DEFAULT_S3_WEBSITE_REGIONS,
)

__all__ = ["CloudBucketScanner", "DEFAULT_S3_WEBSITE_REGIONS"]

logger = logging.getLogger(__name__)


class CloudBucketScannerBase:
    """Base class that owns AWS bucket handling, S3 resilient probes,
    Azure checks, S3-compatible object-store checks, and service probes
    that belong to non-GCP providers."""

    timeout_seconds: int
    concurrency: int
    enable_write_probes: bool
    s3_website_regions: tuple[str, ...]
    s3_object_paths: tuple[str, ...]
    enable_cloud_run_enum: bool
    aws_regions: tuple[str, ...]
    gcp_regions: tuple[str, ...]
    azure_function_regions: tuple[str, ...]
    backblaze_regions: tuple[str, ...]
    wasabi_regions: tuple[str, ...]
    do_regions: tuple[str, ...]
    oci_regions: tuple[str, ...]

    async def scan_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> list[dict[str, Any]]:
        """Run checks across all platforms for a single bucket name."""
        results: list[dict[str, Any]] = []
        aws = await self.check_aws_bucket(session, bucket)
        if aws:
            results.append(aws)
        gcp = await self.check_gcp_bucket(session, bucket)
        if gcp:
            results.append(gcp)
        azure = await self.check_azure_bucket(session, bucket)
        if azure:
            results.append(azure)
        alibaba = await self.check_alibaba_bucket(session, bucket)
        if alibaba:
            results.append(alibaba)
        tencent = await self.check_tencent_bucket(session, bucket)
        if tencent:
            results.append(tencent)
        return results

    async def check_aws_bucket(
        self,
        session: aiohttp.ClientSession,
        bucket: str,
    ) -> dict[str, Any] | None:
        """Check AWS S3 bucket status and permissions."""
        url = f"https://{bucket}.s3.amazonaws.com"
        try:
            finding: dict[str, Any] | None = None
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)
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
                        f"{url}/?acl", timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)
                    ) as acl_resp:
                        finding["permissions"]["read_acl"] = acl_resp.status == 200
                        if acl_resp.status == 200:
                            finding["severity"] = "high"
                            finding["details"] += " ACL is publicly readable."
                except Exception:  # noqa: S110
                    pass

                if self.enable_write_probes:
                    try:
                        async with session.put(
                            f"{url}/cyber_pipeline_write_test.txt",
                            data="test",
                            timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                        ) as put_resp:
                            finding["permissions"]["write"] = put_resp.status == 200
                            if put_resp.status == 200:
                                finding["severity"] = "critical"
                                finding["details"] += (
                                    " Bucket allows unauthenticated file uploads (Public Write)!"
                                )
                    except Exception:  # noqa: S110
                        pass

                website_findings = await self._probe_s3_website(session, bucket)
                if website_findings:
                    finding["permissions"]["static_website"] = True
                    finding["severity"] = "high"
                    finding["details"] += (
                        f" Static-website endpoint(s) public: {', '.join(website_findings)}."
                    )

                public_objects = await self._probe_common_object_paths(session, url)
                if public_objects:
                    finding["permissions"]["public_objects"] = public_objects
                    finding["severity"] = "high"
                    finding["details"] += (
                        f" Publicly readable object(s): {', '.join(public_objects)}."
                    )

                try:
                    async with session.get(
                        f"{url}/?policy",
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                    ) as policy_resp:
                        if policy_resp.status == 200:
                            finding["permissions"]["public_policy"] = True
                            if finding["severity"] not in ("high", "critical"):
                                finding["severity"] = "medium"
                            finding["details"] += " Bucket policy document is publicly readable."
                except Exception:  # noqa: S110
                    pass

                return finding

        except Exception:  # noqa: S110
            pass
        return None

    async def _probe_s3_website(
        self,
        session: aiohttp.ClientSession,
        bucket: str,
    ) -> list[str]:
        from src.recon.cloud_recon.helpers import _probe_s3_website

        return await _probe_s3_website(self, session, bucket)

    async def _probe_common_object_paths(
        self,
        session: aiohttp.ClientSession,
        bucket_url: str,
    ) -> list[str]:
        from src.recon.cloud_recon.helpers import _probe_common_object_paths

        return await _probe_common_object_paths(self, session, bucket_url)

    async def check_gcp_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> dict[str, Any] | None:
        from src.recon.cloud_recon.gcp import GCPCloudRecon

        return await GCPCloudRecon.check_gcp_bucket(cast(Any, self), session, bucket)

    async def check_azure_bucket(
        self,
        session: aiohttp.ClientSession,
        bucket: str,
    ) -> dict[str, Any] | None:
        """Check Azure Blob Storage account status."""
        sanitized_bucket = "".join(c for c in bucket if c.isalnum()).lower()
        if not (3 <= len(sanitized_bucket) <= 24):
            return None
        url = f"https://{sanitized_bucket}.blob.core.windows.net"
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)
            ) as response:
                status = response.status
                if status in {400, 403}:
                    return {
                        "platform": "Azure Blob Storage",
                        "bucket": sanitized_bucket,
                        "url": url,
                        "status": "secure",
                        "severity": "info",
                        "details": "Storage account exists (returned status code). Access is restricted.",
                    }
                if status == 200:
                    return {
                        "platform": "Azure Blob Storage",
                        "bucket": sanitized_bucket,
                        "url": url,
                        "status": "public",
                        "severity": "high",
                        "details": "Storage container endpoint is accessible without authorization.",
                    }
        except Exception:  # noqa: S110
            pass
        return None

    async def check_alibaba_bucket(
        self,
        session: aiohttp.ClientSession,
        bucket: str,
    ) -> dict[str, Any] | None:
        return await self._generic_object_storage_check(
            session,
            bucket=bucket,
            url=f"https://{bucket}.oss-cn-hangzhou.aliyuncs.com",
            platform="Alibaba OSS",
            extra_endpoints=[f"https://{bucket}.oss.aliyuncs.com"],
        )

    async def check_tencent_bucket(
        self,
        session: aiohttp.ClientSession,
        bucket: str,
    ) -> dict[str, Any] | None:
        return await self._generic_object_storage_check(
            session,
            bucket=bucket,
            url=f"https://{bucket}.cos.ap-guangzhou.myqcloud.com",
            platform="Tencent COS",
        )

    async def _generic_object_storage_check(
        self,
        session: aiohttp.ClientSession,
        *,
        bucket: str,
        url: str,
        platform: str,
        extra_endpoints: list[str] | None = None,
    ) -> dict[str, Any] | None:
        from src.recon.cloud_recon.helpers import _generic_object_storage_check

        return await _generic_object_storage_check(
            self,
            session,
            bucket=bucket,
            url=url,
            platform=platform,
            extra_endpoints=extra_endpoints,
        )

    async def probe_aws_lambda_urls(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_aws_lambda_urls

        return await probe_aws_lambda_urls(self, session, project_id)

    async def probe_api_gateway(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_api_gateway

        return await probe_api_gateway(self, session, project_id)

    async def probe_aws_amplify(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_aws_amplify

        return await probe_aws_amplify(self, session, project_id)

    async def probe_firebase_hosting(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_firebase_hosting

        return await probe_firebase_hosting(self, session, project_id)

    async def probe_azure_functions(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_azure_functions

        return await probe_azure_functions(self, session, project_id)

    async def probe_azure_logic_apps(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_azure_logic_apps

        return await probe_azure_logic_apps(self, session, project_id)

    async def probe_azure_static_web_apps(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_azure_static_web_apps

        return await probe_azure_static_web_apps(self, session, project_id)

    async def probe_s3_access_points(
        self,
        session: aiohttp.ClientSession,
        base_name: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_s3_access_points

        return await probe_s3_access_points(self, session, base_name)

    async def probe_multi_region_s3(
        self,
        session: aiohttp.ClientSession,
        bucket: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_multi_region_s3

        return await probe_multi_region_s3(self, session, bucket)

    def _extract_region_from_url(self, url: str) -> str:
        from src.recon.cloud_recon.services import _extract_region_from_url

        return _extract_region_from_url(self, url)

    async def probe_digitalocean_spaces(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_digitalocean_spaces

        return await probe_digitalocean_spaces(self, session, project_id)

    async def probe_backblaze_b2(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_backblaze_b2

        return await probe_backblaze_b2(self, session, project_id)

    async def probe_wasabi(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_wasabi

        return await probe_wasabi(self, session, project_id)

    async def probe_oci_object_storage(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
    ) -> list[dict[str, Any]]:
        from src.recon.cloud_recon.services import probe_oci_object_storage

        return await probe_oci_object_storage(self, session, project_id)

    async def scan_all_candidates(self, target: str) -> list[dict[str, Any]]:
        """Generate and scan all bucket candidates concurrently."""

        from src.recon.cloud_recon.gcp import GCPCloudRecon

        parsed = urlparse(target if "://" in target else f"https://{target}")
        domain = parsed.hostname or parsed.path or target
        core_name = domain.split(".")[0].lower().strip()
        project_id = core_name

        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks: list[asyncio.Task[Any]] = []
            candidates = self.generate_candidates(target)
            if candidates:
                for bucket in candidates:
                    tasks.append(asyncio.create_task(self.scan_bucket(session, bucket)))

            tasks.append(asyncio.create_task(GCPCloudRecon.probe_cloud_run(cast(Any, self), session, target)))
            tasks.append(
                asyncio.create_task(
                    GCPCloudRecon.probe_gcp_cloud_functions(cast(Any, self), session, project_id)
                )
            )
            tasks.append(
                asyncio.create_task(GCPCloudRecon.probe_gcp_app_engine(cast(Any, self), session, project_id))
            )
            tasks.append(asyncio.create_task(self.probe_aws_lambda_urls(session, project_id)))
            tasks.append(asyncio.create_task(self.probe_api_gateway(session, project_id)))
            tasks.append(asyncio.create_task(self.probe_aws_amplify(session, project_id)))
            tasks.append(asyncio.create_task(self.probe_firebase_hosting(session, project_id)))
            tasks.append(asyncio.create_task(self.probe_azure_functions(session, project_id)))
            tasks.append(asyncio.create_task(self.probe_azure_logic_apps(session, project_id)))
            tasks.append(asyncio.create_task(self.probe_azure_static_web_apps(session, project_id)))
            tasks.append(asyncio.create_task(self.probe_s3_access_points(session, core_name)))
            tasks.append(asyncio.create_task(self.probe_multi_region_s3(session, core_name)))
            tasks.append(asyncio.create_task(self.probe_digitalocean_spaces(session, project_id)))
            tasks.append(asyncio.create_task(self.probe_backblaze_b2(session, project_id)))
            tasks.append(asyncio.create_task(self.probe_wasabi(session, project_id)))
            tasks.append(asyncio.create_task(self.probe_oci_object_storage(session, project_id)))

            completed = await asyncio.gather(*tasks, return_exceptions=True)
            findings: list[dict[str, Any]] = []
            for sublist in completed:
                if isinstance(sublist, BaseException):
                    logger.debug("Cloud asset scan failed: %s", sublist)
                    continue
                if isinstance(sublist, list):
                    for item in sublist:
                        if isinstance(item, dict):
                            findings.append(item)
            return findings

    def run_scan_sync(self, target: str) -> list[dict[str, Any]]:
        from src.recon.common import run_async_in_sync_context

        return cast(list[dict[str, Any]], run_async_in_sync_context(self.scan_all_candidates(target)))

    def generate_candidates(self, target: str) -> list[str]:
        """Generate smart storage bucket candidates based on target domain.

        Args:
            target: Target domain or name (e.g. 'example.com')

        Returns:
            List of unique bucket name candidates.
        """
        from urllib.parse import urlparse

        parsed = urlparse(target if "://" in target else f"https://{target}")
        domain = parsed.hostname or parsed.path or target
        core_name = domain.split(".")[0].lower().strip()
        if not core_name:
            return []
        core_names = {core_name}
        if "-" in core_name:
            core_names.add(core_name.replace("-", ""))
        suffixes = [
            "",
            "-backup",
            "-backups",
            "-assets",
            "-public",
            "-private",
            "-prod",
            "-production",
            "-dev",
            "-development",
            "-staging",
            "-stage",
            "-test",
            "-data",
            "-database",
            "-storage",
            "-s3",
            "-bucket",
            "-photos",
            "-images",
            "-logs",
            "-billing",
            "-internal",
            "-cloud",
            "-shares",
            "-files",
            "-archive",
            "-temp",
        ]
        candidates = set()
        for name in core_names:
            for suffix in suffixes:
                candidates.add(f"{name}{suffix}")
                if suffix.startswith("-"):
                    dot_suffix = suffix.replace("-", ".")
                    candidates.add(f"{name}{dot_suffix}")
        return sorted(list(candidates))


class CloudBucketScanner(CloudBucketScannerBase):
    """Public scanner facade that keeps the original single-class surface while
    delegating to the modularized mix-ins internally."""

    def __init__(
        self,
        timeout_seconds: int = 5,
        concurrency: int = 25,
        enable_write_probes: bool = False,
        s3_website_regions: tuple[str, ...] | None = None,
        s3_object_paths: tuple[str, ...] | None = None,
        enable_cloud_run_enum: bool = True,
        aws_regions: tuple[str, ...] | None = None,
        gcp_regions: tuple[str, ...] | None = None,
        azure_function_regions: tuple[str, ...] | None = None,
        backblaze_regions: tuple[str, ...] | None = None,
        wasabi_regions: tuple[str, ...] | None = None,
        do_regions: tuple[str, ...] | None = None,
        oci_regions: tuple[str, ...] | None = None,
    ):
        self.timeout_seconds = timeout_seconds
        self.concurrency = concurrency
        self.enable_write_probes = enable_write_probes
        self.s3_website_regions = s3_website_regions or DEFAULT_S3_WEBSITE_REGIONS
        self.s3_object_paths = s3_object_paths or _S3_COMMON_OBJECT_PATHS
        self.enable_cloud_run_enum = enable_cloud_run_enum
        self.aws_regions = aws_regions or _DEFAULT_AWS_REGIONS
        self.gcp_regions = gcp_regions or _DEFAULT_GCP_REGIONS
        self.azure_function_regions = azure_function_regions or _AZURE_FUNCTIONS_REGIONS
        self.backblaze_regions = backblaze_regions or _BACKBLAZE_REGIONS
        self.wasabi_regions = wasabi_regions or _WASABI_REGIONS
        self.do_regions = do_regions or _DO_REGIONS
        self.oci_regions = oci_regions or _OCI_REGIONS
