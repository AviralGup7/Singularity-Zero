"""Cloud Bucket & Asset Enumeration (Multi-Cloud Recon).

Identifies publicly exposed or writable storage buckets on AWS S3, GCP, and Azure
associated with the target organization.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)


class CloudBucketScanner:
    """Asynchronous multi-cloud storage bucket enumerator."""

    def __init__(self, timeout_seconds: int = 5, concurrency: int = 25):
        self.timeout_seconds = timeout_seconds
        self.concurrency = concurrency

    def generate_candidates(self, target: str) -> list[str]:
        """Generate smart storage bucket candidates based on target domain.

        Args:
            target: Target domain or name (e.g. 'example.com')

        Returns:
            List of unique bucket name candidates.
        """
        # Parse core domain name
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
                # Also support standard dot notation
                if suffix.startswith("-"):
                    dot_suffix = suffix.replace("-", ".")
                    candidates.add(f"{name}{dot_suffix}")

        return sorted(list(candidates))

    async def check_aws_bucket(
        self, session: aiohttp.ClientSession, bucket: str
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

            if finding:
                # Active Probe 1: Check ACL readability
                try:
                    async with session.get(
                        f"{url}/?acl", timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)
                    ) as acl_resp:
                        finding["permissions"]["read_acl"] = acl_resp.status == 200
                        if acl_resp.status == 200:
                            finding["severity"] = "high"
                            finding["details"] += " ACL is publicly readable."
                except Exception:
                    pass

                # Active Probe 2: Check Public Write (Upload)
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
                except Exception:
                    pass

                return finding

        except Exception:  # noqa: S110
            pass
        return None

    async def check_gcp_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> dict[str, Any] | None:
        """Check Google Cloud Storage bucket status and permissions."""
        url = f"https://storage.googleapis.com/{bucket}"
        try:
            finding: dict[str, Any] | None = None
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)
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
                # Active Probe 1: Check ACL readability
                try:
                    async with session.get(
                        f"{url}?acl", timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)
                    ) as acl_resp:
                        finding["permissions"]["read_acl"] = acl_resp.status == 200
                        if acl_resp.status == 200:
                            finding["severity"] = "high"
                            finding["details"] += " ACL is publicly readable."
                except Exception:
                    pass

                # Active Probe 2: Check Public Write (Upload)
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
                except Exception:
                    pass

                return finding

        except Exception:  # noqa: S110
            pass
        return None

    async def check_azure_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> dict[str, Any] | None:
        """Check Azure Blob Storage account status."""
        # Azure storage accounts must be 3-24 characters, numbers and lowercase letters only
        sanitized_bucket = "".join(c for c in bucket if c.isalnum()).lower()
        if not (3 <= len(sanitized_bucket) <= 24):
            return None

        url = f"https://{sanitized_bucket}.blob.core.windows.net"
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)
            ) as response:
                # If we get 400 (InvalidHeader/Bad Request) or 403, the storage account exists!
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
                elif status == 200:
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
        return results

    async def scan_all_candidates(self, target: str) -> list[dict[str, Any]]:
        """Generate and scan all bucket candidates concurrently."""
        candidates = self.generate_candidates(target)
        if not candidates:
            return []

        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.scan_bucket(session, bucket) for bucket in candidates]
            # Run tasks concurrently
            completed = await asyncio.gather(*tasks)
            # Flatten results list
            findings = []
            for sublist in completed:
                findings.extend(sublist)
            return findings

    def run_scan_sync(self, target: str) -> list[dict[str, Any]]:
        """Synchronous runner wrapper for the async scan."""
        from src.recon.common import run_async_in_sync_context

        return cast(list[dict[str, Any]], run_async_in_sync_context(self.scan_all_candidates(target)))
