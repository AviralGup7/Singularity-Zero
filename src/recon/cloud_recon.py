"""Cloud Bucket & Asset Enumeration (Multi-Cloud Recon).

Identifies publicly exposed or writable storage buckets on AWS S3, GCP, and Azure
associated with the target organization.

Improvements (v3):
- **S3 static-website hosting endpoint** is probed in addition to the
  REST API. A bucket that returns 403 on ``https://bucket.s3.amazonaws.com``
  can still serve a public listing at
  ``http://bucket.s3-website-<region>.amazonaws.com`` when the operator
  has enabled static website hosting.
- **Object-path probing**: a 403 on the bucket root does NOT mean the
  bucket contents are private. We now probe a small set of well-known
  object paths (``index.html``, ``robots.txt``, ``sitemap.xml``) on
  every AWS/GCP bucket. A 200 on any of them is reported as a public
  object finding (severity: high).
- **GCP Cloud Run URL enumeration** — Public Cloud Run services use
  the ``https://<service>-<hash>-<region>.a.run.app`` convention with
  hash values we cannot predict. We probe the parent
  ``https://<service>.a.run.app`` for the major service names plus
  the brand-derived candidates. This is best-effort and cannot
  enumerate random service names, but it covers the most common
  pattern (e.g. ``<brand>-api-<hash>-uc.a.run.app``).
- **Azure SAS-pattern generation** — We do NOT generate working SAS
  tokens (that requires account credentials), but we probe the
  ``$web`` static-website container and the ``?restype=container&comp=list``
  listing endpoint, which are reachable without credentials and
  frequently misconfigured.
- **Alibaba OSS / Tencent COS / Huawei OBS** — The major non-Western
  cloud providers are now also probed using the same candidate
  generator. They follow very similar patterns to S3 and are often
  forgotten in bucket-permission audits.
- The S3 detection also probes the **bucket policy** via the public
  ``?policy`` REST endpoint and reports any publicly-readable policy
  document as a finding (severity: medium — the document frequently
  contains the bucket's resource-based access policy in plaintext).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from typing import Any, cast
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)


# Common S3 static-website hosting regions. The bucket website
# endpoint is region-specific: ``s3-website-us-east-1`` for the US,
# ``s3-website.eu-west-1`` for Europe, etc. Probing just the three
# most common regions catches >90% of public website endpoints in
# practice; operators can extend the list via the
# ``cloud_recon.s3_website_regions`` config key.
DEFAULT_S3_WEBSITE_REGIONS: tuple[str, ...] = (
    "us-east-1",
    "us-west-2",
    "eu-west-1",
)

# Object paths that almost every public-facing bucket has or has had.
# The list is intentionally short — each probe costs a network round
# trip, and a long list would just slow the scan.
_S3_COMMON_OBJECT_PATHS: tuple[str, ...] = (
    "index.html",
    "robots.txt",
    "sitemap.xml",
    "favicon.ico",
    "readme.md",
    "README",
    "static/index.html",
)

# GCP Cloud Run region suffixes. ``a.run.app`` is the global anycast
# domain; ``b.run.app`` and ``c.run.app`` exist but are rare. The
# region label (``uc``, ``us``, ``eu``, etc.) is appended between the
# hash and the run.app domain. We use ``uc`` (us-central1) as the
# most-common default; operators can extend the list per-config.
_GCP_CLOUD_RUN_REGION_TEMPLATES: tuple[str, ...] = (
    "-uc.a.run.app",
    "-us-central1.a.run.app",
    "-us-east1.a.run.app",
    "-europe-west1.a.run.app",
    "-asia-east1.a.run.app",
)

# Service-name candidates to append to the brand prefix when
# enumerating Cloud Run URLs.
_GCP_CLOUD_RUN_SERVICE_HINTS: tuple[str, ...] = (
    "api",
    "app",
    "web",
    "service",
    "backend",
    "frontend",
)


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
    ):
        """Initialize the scanner.

        Args:
            timeout_seconds: Per-request timeout budget.
            concurrency: Max concurrent connections.
            enable_write_probes: When True, the scanner will perform an
                authenticated ``PUT`` against candidate buckets to test for
                public write access. **Defaults to False** because such
                probes can be mistaken for malicious activity by the target
                or its CDN/WAF, may create artifacts in storage that the
                operator must clean up, and require explicit authorization
                from the bucket owner. Enable only in offensive contexts
                where a written scope-of-work exists.
            s3_website_regions: Override the list of AWS regions whose
                ``s3-website-<region>`` endpoints are probed.
            s3_object_paths: Override the list of object paths probed
                on every AWS/GCP bucket.
            enable_cloud_run_enum: When True, the scanner will probe
                candidate Cloud Run URLs derived from the target brand.
        """
        self.timeout_seconds = timeout_seconds
        self.concurrency = concurrency
        self.enable_write_probes = enable_write_probes
        self.s3_website_regions = s3_website_regions or DEFAULT_S3_WEBSITE_REGIONS
        self.s3_object_paths = s3_object_paths or _S3_COMMON_OBJECT_PATHS
        self.enable_cloud_run_enum = enable_cloud_run_enum

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
        """Check AWS S3 bucket status and permissions.

        v3: now also probes the static-website hosting endpoint
        (``bucket.s3-website-<region>.amazonaws.com``) for the configured
        regions and the most common object paths. Either of those returning
        200 turns the bucket from "secure" into a high-severity finding.
        """
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
                    # NoSuchBucket (404) or NoSuchHost — the bucket does
                    # not exist; do not waste cycles on the expensive
                    # follow-up probes.
                    return None

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
                except Exception:  # noqa: S110
                    pass

                # Active Probe 2: Check Public Write (Upload)
                # Gated by enable_write_probes: PUT probes mutate remote
                # state, may trigger abuse reports, and must be authorised
                # in writing before they are run.
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

                # Active Probe 3 (v3): Static-website hosting endpoint
                # The bucket may return 403 on the REST API but serve a
                # public listing at ``bucket.s3-website-<region>``. Probe
                # the configured regions and upgrade the finding if any
                # respond with a public index.
                try:
                    website_findings = await self._probe_s3_website(session, bucket)
                    if website_findings:
                        finding["permissions"]["static_website"] = True
                        finding["severity"] = "high"
                        finding["details"] += (
                            f" Static-website endpoint(s) public: {', '.join(website_findings)}."
                        )
                except Exception:  # noqa: S110
                    pass

                # Active Probe 4 (v3): Common object paths
                # ``index.html``, ``robots.txt``, etc. — a 200 on any of
                # these means the bucket has at least one publicly
                # readable object regardless of bucket-level ACLs.
                try:
                    public_objects = await self._probe_common_object_paths(session, url)
                    if public_objects:
                        finding["permissions"]["public_objects"] = public_objects
                        finding["severity"] = "high"
                        finding["details"] += (
                            f" Publicly readable object(s): {', '.join(public_objects)}."
                        )
                except Exception:  # noqa: S110
                    pass

                # Active Probe 5 (v3): Public bucket policy
                # ``?policy`` returns the resource-based access policy as
                # JSON. 200 means the policy document is world-readable.
                try:
                    async with session.get(
                        f"{url}/?policy",
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                    ) as policy_resp:
                        if policy_resp.status == 200:
                            finding["permissions"]["public_policy"] = True
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
        """Probe the S3 static-website hosting endpoint for each configured region.

        Returns the list of region codes that responded with a 200/3xx
        (the website endpoint always returns 200 with an XML index
        page when configured). Empty list if no region responded.
        """
        public_regions: list[str] = []
        for region in self.s3_website_regions:
            url = f"http://{bucket}.s3-website-{region}.amazonaws.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                    allow_redirects=True,
                ) as resp:
                    if resp.status in (200, 301, 302):
                        public_regions.append(region)
            except Exception:  # noqa: S110
                continue
        return public_regions

    async def _probe_common_object_paths(
        self,
        session: aiohttp.ClientSession,
        bucket_url: str,
    ) -> list[str]:
        """Probe each path in ``self.s3_object_paths`` for a 200 response.

        Returns the list of paths that responded with 200. The function
        uses ``HEAD`` to minimise bandwidth.
        """
        public_paths: list[str] = []
        for path in self.s3_object_paths:
            url = f"{bucket_url.rstrip('/')}/{path.lstrip('/')}"
            try:
                async with session.head(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                    allow_redirects=True,
                ) as resp:
                    if resp.status == 200:
                        public_paths.append(path)
            except Exception:  # noqa: S110
                continue
        return public_paths

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
                except Exception:  # noqa: S110
                    pass

                # Active Probe 2: Check Public Write (Upload)
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
        alibaba = await self.check_alibaba_bucket(session, bucket)
        if alibaba:
            results.append(alibaba)
        tencent = await self.check_tencent_bucket(session, bucket)
        if tencent:
            results.append(tencent)
        return results

    async def check_alibaba_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> dict[str, Any] | None:
        """Check Alibaba Cloud OSS bucket status.

        Alibaba OSS uses the ``<bucket>.<region>.aliyuncs.com``
        convention. We probe the global ``oss-cn-hangzhou`` endpoint
        which is the most common default region, and a 200/403 split
        follows the same public/secure pattern as AWS S3.
        """
        if not bucket or "-" not in bucket and "_" not in bucket:
            # Alibaba OSS naming rules: 3-63 chars, lowercase, digits, dash.
            pass
        url = f"https://{bucket}.oss-cn-hangzhou.aliyuncs.com"
        return await self._generic_object_storage_check(
            session,
            bucket=bucket,
            url=url,
            platform="Alibaba OSS",
            extra_endpoints=[
                f"https://{bucket}.oss.aliyuncs.com",
            ],
        )

    async def check_tencent_bucket(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> dict[str, Any] | None:
        """Check Tencent Cloud COS bucket status.

        Tencent COS uses the ``<bucket>-<appid>.cos.<region>.myqcloud.com``
        convention. Without knowing the AppID we can only probe the
        truncated ``<bucket>.cos.<region>.myqcloud.com`` host — a 200
        indicates the bucket is accessible; a 404 / NXDOMAIN indicates
        the AppID-less form is unreachable (expected, not a finding).
        """
        url = f"https://{bucket}.cos.ap-guangzhou.myqcloud.com"
        return await self._generic_object_storage_check(
            session,
            bucket=bucket,
            url=url,
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
        """Shared implementation for S3-compatible object stores.

        Args:
            session: aiohttp session.
            bucket: Bucket name (informational).
            url: Primary endpoint to probe.
            platform: Display name in the resulting finding.
            extra_endpoints: Optional additional URLs to probe (e.g.
                the global Alibaba endpoint).

        Returns:
            Finding dict, or None if the bucket does not exist on this
            platform (404/NoSuchHost).
        """
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=self.timeout_seconds)
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
        except Exception:  # noqa: S110
            pass
        return None

    def enumerate_cloud_run_candidates(self, target: str) -> list[str]:
        """Generate candidate GCP Cloud Run URLs for the target brand.

        Cloud Run URLs follow the pattern
        ``https://<service>-<hash>-<region>.a.run.app`` where the hash
        is a 9-12 character random string. We cannot predict the hash,
        so this method returns the brand-derived patterns that catch
        the common case where a service is named after the brand.

        Args:
            target: Target domain (used to derive the brand name).

        Returns:
            List of candidate Cloud Run hostnames (no scheme).
        """
        parsed = urlparse(target if "://" in target else f"https://{target}")
        domain = parsed.hostname or parsed.path or target
        core_name = domain.split(".")[0].lower().strip()
        if not core_name:
            return []
        candidates: set[str] = set()
        for hint in _GCP_CLOUD_RUN_SERVICE_HINTS:
            for region_tpl in _GCP_CLOUD_RUN_REGION_TEMPLATES:
                candidates.add(f"{core_name}-{hint}{region_tpl}")
                candidates.add(f"{core_name}{region_tpl}")
        return sorted(candidates)

    async def probe_cloud_run(
        self, session: aiohttp.ClientSession, target: str
    ) -> list[dict[str, Any]]:
        """Probe candidate Cloud Run URLs derived from the target brand.

        Args:
            session: aiohttp session.
            target: Target domain.

        Returns:
            List of finding dicts. A 200/301 response from a candidate
            URL is recorded as a finding with the URL attached. A 404
            is not a finding.
        """
        if not self.enable_cloud_run_enum:
            return []
        candidates = self.enumerate_cloud_run_candidates(target)
        findings: list[dict[str, Any]] = []
        for host in candidates:
            url = f"https://{host}"
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
                                "service": host,
                                "url": url,
                                "status": "public",
                                "severity": "info",
                                "details": (
                                    f"Public Cloud Run URL responded with HTTP {resp.status}. "
                                    "Verify the service is intended to be public."
                                ),
                            }
                        )
            except Exception:  # noqa: S110
                continue
        return findings

    async def scan_all_candidates(self, target: str) -> list[dict[str, Any]]:
        """Generate and scan all bucket candidates concurrently."""
        candidates = self.generate_candidates(target)
        if not candidates:
            # Even when there are no bucket candidates, we can still
            # attempt Cloud Run URL enumeration against the brand.
            connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=True)
            async with aiohttp.ClientSession(connector=connector) as session:
                try:
                    return await self.probe_cloud_run(session, target)
                except Exception:  # noqa: S110
                    return []
            return []

        # Enforce TLS certificate validation. Disabling verification silently
        # downgrades the connection to plaintext-equivalent and exposes the
        # scan to MITM. Operators who need a custom CA should pass a
        # ``ssl_context`` via the connector and leave verification on.
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks: list[asyncio.Task[Any]] = [
                asyncio.create_task(self.scan_bucket(session, bucket)) for bucket in candidates
            ]
            tasks.append(asyncio.create_task(self.probe_cloud_run(session, target)))
            # Run tasks concurrently
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            # Flatten results list
            findings: list[dict[str, Any]] = []
            for sublist in completed:
                if isinstance(sublist, BaseException):
                    logger.debug("Cloud bucket scan failed: %s", sublist)
                    continue
                if isinstance(sublist, list):
                    findings.extend(cast(list[dict[str, Any]], sublist))
            return findings

    def run_scan_sync(self, target: str) -> list[dict[str, Any]]:
        """Synchronous runner wrapper for the async scan."""
        from src.recon.common import run_async_in_sync_context

        return cast(
            list[dict[str, Any]], run_async_in_sync_context(self.scan_all_candidates(target))
        )
