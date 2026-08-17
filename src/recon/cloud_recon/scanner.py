"""CloudBucketScanner — async multi-cloud storage bucket enumerator."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, cast
from urllib.parse import urlparse

import aiohttp

from src.recon.cloud_recon.candidates import (
    build_cloud_run_1st_gen_candidates,
    build_cloud_run_2nd_gen_candidates,
    enumerate_cloud_run_candidates,
    generate_candidates,
)
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
from src.recon.cloud_recon.providers import (
    check_alibaba_bucket,
    check_aws_bucket,
    check_azure_bucket,
    check_gcp_bucket,
    check_tencent_bucket,
    probe_api_gateway,
    probe_aws_amplify,
    probe_aws_lambda_urls,
    probe_azure_functions,
    probe_azure_logic_apps,
    probe_azure_static_web_apps,
    probe_backblaze_b2,
    probe_digitalocean_spaces,
    probe_firebase_hosting,
    probe_gcp_app_engine,
    probe_gcp_cloud_functions,
    probe_multi_region_s3,
    probe_oci_object_storage,
    probe_s3_access_points,
    probe_wasabi,
)

logger = logging.getLogger(__name__)


class CloudBucketScanner:
    """Asynchronous multi-cloud storage bucket enumerator."""

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

    def generate_candidates(self, target: str) -> list[str]:
        """Generate smart storage bucket candidates based on target domain."""
        return generate_candidates(target)

    def enumerate_cloud_run_candidates(self, target: str) -> list[str]:
        """Generate candidate GCP Cloud Run URLs for the target brand."""
        return enumerate_cloud_run_candidates(target)

    async def check_aws_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> dict[str, Any] | None:
        return await check_aws_bucket(
            session,
            bucket,
            timeout_seconds=self.timeout_seconds,
            enable_write_probes=self.enable_write_probes,
            s3_website_regions=self.s3_website_regions,
            s3_object_paths=self.s3_object_paths,
        )

    async def check_gcp_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> dict[str, Any] | None:
        return await check_gcp_bucket(
            session,
            bucket,
            timeout_seconds=self.timeout_seconds,
            enable_write_probes=self.enable_write_probes,
        )

    async def check_azure_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> dict[str, Any] | None:
        return await check_azure_bucket(
            session,
            bucket,
            timeout_seconds=self.timeout_seconds,
        )

    async def check_alibaba_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> dict[str, Any] | None:
        return await check_alibaba_bucket(
            session,
            bucket,
            timeout_seconds=self.timeout_seconds,
        )

    async def check_tencent_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> dict[str, Any] | None:
        return await check_tencent_bucket(
            session,
            bucket,
            timeout_seconds=self.timeout_seconds,
        )

    async def scan_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> list[dict[str, Any]]:
        """Run checks across all platforms for a single bucket name."""
        results = []
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

    async def probe_cloud_run(
        self, session: aiohttp.ClientSession, target: str
    ) -> list[dict[str, Any]]:
        candidate_urls: set[str] = set()
        candidate_urls.update(
            build_cloud_run_1st_gen_candidates(
                target,
                enable_cloud_run_enum=self.enable_cloud_run_enum,
            )
        )
        candidate_urls.update(
            build_cloud_run_2nd_gen_candidates(
                target,
                enable_cloud_run_enum=self.enable_cloud_run_enum,
                gcp_regions=self.gcp_regions,
            )
        )
        findings: list[dict[str, Any]] = []
        for candidate_url in candidate_urls:
            url = f"https://{candidate_url}"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 301, 302):
                        findings.append(
                            {
                                "platform": "GCP Cloud Run",
                                "service": candidate_url,
                                "url": url,
                                "status": "public",
                                "severity": "info",
                                "details": (
                                    f"Public Cloud Run URL responded with HTTP {resp.status}. "
                                    "Verify the service is intended to be public."
                                ),
                            }
                        )
            except Exception:
                logger.debug("Cloud Run probe failed for %s", url)
                continue
        return findings

    async def scan_all_candidates(self, target: str) -> list[dict[str, Any]]:
        """Generate and scan all bucket candidates concurrently."""
        parsed = urlparse(target if "://" in target else f"https://{target}")
        domain = parsed.hostname or parsed.path or target
        core_name = domain.split(".")[0].lower().strip()
        project_id = core_name

        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=True)
        sem = asyncio.Semaphore(self.concurrency)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks: set[asyncio.Task[Any]] = set()
            candidates = self.generate_candidates(target)

            async def _bounded(coro: Any) -> Any:
                async with sem:
                    return await coro

            if candidates:
                for bucket in candidates:
                    t = asyncio.create_task(_bounded(self.scan_bucket(session, bucket)))
                    tasks.add(t)
                    t.add_done_callback(tasks.discard)

            for coro in (
                self.probe_cloud_run(session, target),
                probe_gcp_cloud_functions(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                    gcp_regions=self.gcp_regions,
                ),
                probe_gcp_app_engine(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                ),
                probe_aws_lambda_urls(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                    aws_regions=self.aws_regions,
                ),
                probe_api_gateway(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                    aws_regions=self.aws_regions,
                ),
                probe_aws_amplify(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                ),
                probe_firebase_hosting(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                ),
                probe_azure_functions(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                    azure_function_regions=self.azure_function_regions,
                ),
                probe_azure_logic_apps(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                    azure_function_regions=self.azure_function_regions,
                ),
                probe_azure_static_web_apps(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                ),
                probe_s3_access_points(
                    session,
                    core_name,
                    timeout_seconds=self.timeout_seconds,
                    aws_regions=self.aws_regions,
                ),
                probe_multi_region_s3(
                    session,
                    core_name,
                    timeout_seconds=self.timeout_seconds,
                    aws_regions=self.aws_regions,
                ),
                probe_digitalocean_spaces(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                    do_regions=self.do_regions,
                ),
                probe_backblaze_b2(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                    backblaze_regions=self.backblaze_regions,
                ),
                probe_wasabi(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                    wasabi_regions=self.wasabi_regions,
                ),
                probe_oci_object_storage(
                    session,
                    project_id,
                    timeout_seconds=self.timeout_seconds,
                    oci_regions=self.oci_regions,
                ),
            ):
                t = asyncio.create_task(_bounded(coro))
                tasks.add(t)
                t.add_done_callback(tasks.discard)

            completed = await asyncio.gather(*tasks, return_exceptions=True)
            findings: list[dict[str, Any]] = []
            for sublist in completed:
                if isinstance(sublist, BaseException):
                    logger.debug("Cloud asset scan failed: %s", sublist)
                    continue
                if isinstance(sublist, list):
                    for item in sublist:
                        if isinstance(item, dict):
                            findings.append(cast(dict[str, Any], item))
            return findings

    def run_scan_sync(self, target: str) -> list[dict[str, Any]]:
        """Synchronous runner wrapper for the async scan."""
        from src.recon.common import run_async_in_sync_context

        return cast(
            list[dict[str, Any]], run_async_in_sync_context(self.scan_all_candidates(target))
        )
