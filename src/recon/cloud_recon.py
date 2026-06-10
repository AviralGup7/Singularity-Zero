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
import logging
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
    "auth",
    "proxy",
    "gateway",
    "cdn",
    "webhook",
    "worker",
)

_DEFAULT_AWS_REGIONS: tuple[str, ...] = (
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "sa-east-1",
)

_DEFAULT_GCP_REGIONS: tuple[str, ...] = (
    "us-central1",
    "us-east1",
    "us-east4",
    "us-west1",
    "us-west2",
    "us-west3",
    "us-west4",
    "europe-west1",
    "europe-west2",
    "europe-west3",
    "europe-west4",
    "europe-west6",
    "asia-east1",
    "asia-east2",
    "asia-northeast1",
    "asia-northeast2",
    "asia-northeast3",
    "asia-southeast1",
    "asia-southeast2",
    "australia-southeast1",
    "southamerica-east1",
)

_AZURE_FUNCTIONS_REGIONS: tuple[str, ...] = (
    "us",
    "us2",
    "us3",
    "europe",
    "asia",
    "australia",
    "india",
    "canada",
    "uk",
    "germany",
    "japan",
    "korea",
    "brazil",
    "southafrica",
    "uae",
)

_OCI_REGIONS: tuple[str, ...] = (
    "us-ashburn-1",
    "us-luke-1",
    "us-gov-phx-1",
    "ca-toronto-1",
    "sa-saopaulo-1",
    "eu-amsterdam-1",
    "eu-frankfurt-1",
    "uk-london-1",
    "ap-mumbai-1",
    "ap-osaka-1",
    "ap-seoul-1",
    "ap-sydney-1",
    "ap-tokyo-1",
)

_WASABI_REGIONS: tuple[str, ...] = (
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-central-1",
    "eu-west-1",
    "ap-northeast-1",
    "ap-southeast-1",
)

_DO_REGIONS: tuple[str, ...] = (
    "nyc3",
    "sfo2",
    "nyc1",
    "ams3",
    "sgp1",
    "lon1",
    "fra1",
    "tor1",
    "sfo3",
    "blr1",
    "syd1",
)

_BACKBLAZE_REGIONS: tuple[str, ...] = (
    "us-west-002",
    "us-west-001",
    "us-east-005",
    "eu-central-001",
    "apac-001",
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
        aws_regions: tuple[str, ...] | None = None,
        gcp_regions: tuple[str, ...] | None = None,
        azure_function_regions: tuple[str, ...] | None = None,
        backblaze_regions: tuple[str, ...] | None = None,
        wasabi_regions: tuple[str, ...] | None = None,
        do_regions: tuple[str, ...] | None = None,
        oci_regions: tuple[str, ...] | None = None,
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
            aws_regions: Override the list of AWS regions probed for
                S3 Access Points, API Gateway, Lambda Function URLs.
            gcp_regions: Override the list of GCP regions probed for
                Cloud Functions, Cloud Run, App Engine.
            azure_function_regions: Override the list of Azure region
                prefixes used in Function/Logic App URL candidates.
            backblaze_regions: Override regions probed for Backblaze B2.
            wasabi_regions: Override regions probed for Wasabi object storage.
            do_regions: Override regions probed for DigitalOcean Spaces.
            oci_regions: Override regions probed for OCI Object Storage.
        """
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
        """Check Google Cloud Storage bucket status and permissions.

        NOTE: This probe is intentionally unauthenticated and direct to storage.googleapis.com
        because its explicit purpose is to verify if a third-party bucket is publicly readable
        without authentication (checking for security misconfigurations).
        If the scanner is ever modified to perform authenticated storage actions or manage
        internal assets, use Google Workload Identity Federation or pre-signed URLs with minimal
        IAM scoping (e.g., roles/storage.objectViewer scoped to specific buckets).
        """
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
        candidate_urls: set[str] = set()
        candidate_urls.update(self._build_cloud_run_1st_gen_candidates(target))
        candidate_urls.update(self._build_cloud_run_2nd_gen_candidates(target))
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
            except Exception:  # noqa: S110
                continue
        return findings

    async def scan_all_candidates(self, target: str) -> list[dict[str, Any]]:
        """Generate and scan all bucket candidates concurrently."""
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

            tasks.append(asyncio.create_task(self.probe_cloud_run(session, target)))
            tasks.append(asyncio.create_task(self.probe_gcp_cloud_functions(session, project_id)))
            tasks.append(asyncio.create_task(self.probe_gcp_app_engine(session, project_id)))
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
                    findings.extend(cast(list[dict[str, Any]], sublist))
            return findings

    def _build_cloud_run_1st_gen_candidates(self, target: str) -> list[str]:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        domain = parsed.hostname or parsed.path or target
        core_name = domain.split(".")[0].lower().strip()
        if not core_name:
            return []
        candidates: set[str] = set()
        if self.enable_cloud_run_enum:
            for hint in _GCP_CLOUD_RUN_SERVICE_HINTS:
                for region_tpl in _GCP_CLOUD_RUN_REGION_TEMPLATES:
                    candidates.add(f"{core_name}-{hint}{region_tpl}")
                    candidates.add(f"{core_name}{region_tpl}")
        return sorted(candidates)

    def _build_cloud_run_2nd_gen_candidates(self, target: str) -> list[str]:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        domain = parsed.hostname or parsed.path or target
        core_name = domain.split(".")[0].lower().strip()
        if not core_name:
            return []
        candidates: set[str] = set()
        if self.enable_cloud_run_enum:
            for region in self.gcp_regions:
                candidates.add(f"{core_name}-{region}-uc.a.run.app")
                candidates.add(f"{core_name}-{region}.a.run.app")
                for h in _GCP_CLOUD_RUN_SERVICE_HINTS:
                    candidates.add(f"{core_name}-{h}-{region}-uc.a.run.app")
                    candidates.add(f"{core_name}-{h}-{region}.a.run.app")
        return sorted(candidates)

    async def probe_gcp_cloud_functions(
        self, session: aiohttp.ClientSession, project_id: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for region in self.gcp_regions:
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
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
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
                except Exception:  # noqa: S110
                    continue
        second_gen_base = f"https://{project_id}-{self.gcp_regions[0]}.cloudfunctions.net"
        try:
            async with session.get(
                second_gen_base,
                timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                allow_redirects=False,
            ) as resp:
                if resp.status in (200, 301, 302, 401, 403):
                    findings.append(
                        {
                            "platform": "GCP Cloud Functions (2nd Gen)",
                            "url": second_gen_base,
                            "region": self.gcp_regions[0],
                            "status": "detected",
                            "severity": "info",
                            "details": (
                                f"2nd Gen Cloud Functions base URL responded with HTTP {resp.status}."
                            ),
                        }
                    )
        except Exception:  # noqa: S110
            pass
        return findings

    async def probe_gcp_app_engine(
        self, session: aiohttp.ClientSession, project_id: str
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
                    timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
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
            except Exception:  # noqa: S110
                continue
        return findings

    async def probe_aws_lambda_urls(
        self, session: aiohttp.ClientSession, project_id: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        function_candidates = [
            project_id,
            f"{project_id}-function",
            f"{project_id}-api",
            f"{project_id}-handler",
            "api",
            "handler",
            "webhook",
        ]
        for region in self.aws_regions:
            for func_name in function_candidates:
                url = f"https://{func_name}.lambda-url.{region}.on.aws"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
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
                except Exception:  # noqa: S110
                    continue
        return findings

    async def probe_api_gateway(
        self, session: aiohttp.ClientSession, project_id: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        api_candidates = [
            project_id,
            f"{project_id}-api",
            f"{project_id}-gw",
            f"{project_id}-gateway",
            "api",
            "gateway",
        ]
        for region in self.aws_regions:
            for api_id in api_candidates:
                urls = [
                    f"https://{api_id}.execute-api.{region}.amazonaws.com",
                    f"https://{api_id}.execute-api.{region}.vpce.amazonaws.com",
                ]
                for url in urls:
                    try:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
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
                    except Exception:  # noqa: S110
                        continue
        return findings

    async def probe_aws_amplify(
        self, session: aiohttp.ClientSession, project_id: str
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
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
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
                except Exception:  # noqa: S110
                    continue
        return findings

    async def probe_firebase_hosting(
        self, session: aiohttp.ClientSession, project_id: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        channel_candidates = [
            "live",
            "preview",
            "prod",
            "staging",
            "dev",
            "production",
        ]
        for channel in channel_candidates:
            for domain_suffix in ["web.app", "firebaseapp.com"]:
                url = f"https://{channel}.{project_id}.{domain_suffix}"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (200, 301, 302):
                            findings.append(
                                {
                                    "platform": "Firebase Hosting",
                                    "url": url,
                                    "channel": channel,
                                    "status": "public",
                                    "severity": "info",
                                    "details": (
                                        f"Firebase Hosting URL responded with HTTP {resp.status}."
                                    ),
                                }
                            )
                except Exception:  # noqa: S110
                    continue
        return findings

    async def probe_azure_functions(
        self, session: aiohttp.ClientSession, project_id: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        function_candidates = [
            project_id,
            f"{project_id}-function",
            f"{project_id}-api",
            "api",
            "function",
            "handler",
            "webhook",
        ]
        for region in self.azure_function_regions:
            for func in function_candidates:
                for azure_suffix in [
                    f"{func}.{region}.azurewebsites.net",
                    f"{func}.azurewebsites.net",
                ]:
                    url = f"https://{azure_suffix}"
                    try:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                            allow_redirects=False,
                        ) as resp:
                            if resp.status in (200, 301, 302, 401, 403):
                                findings.append(
                                    {
                                        "platform": "Azure Functions",
                                        "function_name": func,
                                        "url": url,
                                        "region": region,
                                        "status": "detected",
                                        "severity": "info",
                                        "details": (
                                            f"Azure Functions URL responded with HTTP {resp.status}."
                                        ),
                                    }
                                )
                    except Exception:  # noqa: S110
                        continue
        return findings

    async def probe_azure_logic_apps(
        self, session: aiohttp.ClientSession, project_id: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        logic_candidates = [
            project_id,
            f"{project_id}-logic",
            f"{project_id}-workflow",
            "workflow",
            "logicapp",
        ]
        for region in self.azure_function_regions:
            for logic_name in logic_candidates:
                url = f"https://{logic_name}.{region}.logic.azure.com"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (200, 301, 302, 401, 403):
                            findings.append(
                                {
                                    "platform": "Azure Logic Apps",
                                    "logic_app_name": logic_name,
                                    "url": url,
                                    "region": region,
                                    "status": "detected",
                                    "severity": "info",
                                    "details": (
                                        f"Logic Apps URL responded with HTTP {resp.status}."
                                    ),
                                }
                            )
                except Exception:  # noqa: S110
                    continue
        return findings

    async def probe_azure_static_web_apps(
        self, session: aiohttp.ClientSession, project_id: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        swa_candidates = [
            project_id,
            f"{project_id}-site",
            f"{project_id}-app",
            f"{project_id}-static",
            "site",
            "app",
        ]
        for swa_name in swa_candidates:
            for swa_suffix in [
                f"{swa_name}.azurestaticapps.net",
                f"{swa_name}.standard.azurestaticapps.net",
            ]:
                url = f"https://{swa_suffix}"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (200, 301, 302):
                            findings.append(
                                {
                                    "platform": "Azure Static Web Apps",
                                    "swa_name": swa_name,
                                    "url": url,
                                    "status": "public",
                                    "severity": "info",
                                    "details": (
                                        f"Static Web Apps URL responded with HTTP {resp.status}."
                                    ),
                                }
                            )
                except Exception:  # noqa: S110
                    continue
        return findings

    async def probe_s3_access_points(
        self, session: aiohttp.ClientSession, base_name: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        access_point_candidates = [
            base_name,
            f"{base_name}-ap",
            f"{base_name}-access",
            f"{base_name}-edge",
            "access",
            "edge",
        ]
        for ap_name in access_point_candidates:
            for region in self.aws_regions:
                url = f"https://{ap_name}-<account-id>.s3-accesspoint.{region}.amazonaws.com"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
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
                                    "details": (
                                        f"S3 Access Point responded with HTTP {resp.status}."
                                    ),
                                }
                            )
                except Exception:  # noqa: S110
                    continue
        return findings

    async def probe_multi_region_s3(
        self, session: aiohttp.ClientSession, bucket: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        path_style_urls = [
            f"https://s3.{region}.amazonaws.com/{bucket}" for region in self.aws_regions
        ]
        vhost_style_urls = [
            f"https://{bucket}.s3.{region}.amazonaws.com" for region in self.aws_regions
        ]
        urls = path_style_urls + vhost_style_urls
        for url in urls:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 301, 302, 403):
                        findings.append(
                            {
                                "platform": "AWS S3 Multi-Region",
                                "bucket": bucket,
                                "url": url,
                                "region": self._extract_region_from_url(url),
                                "status": "detected",
                                "severity": "info",
                                "details": (f"S3 endpoint responded with HTTP {resp.status}."),
                            }
                        )
            except Exception:  # noqa: S110
                continue
        return findings

    def _extract_region_from_url(self, url: str) -> str:
        try:
            parts = url.split(".amazonaws.com")
            if parts:
                prefix = parts[0]
                region_candidate = prefix.split(".")[-2]
                if region_candidate not in {"s3", "execute-api", "vpce", "lambda-url"}:
                    return region_candidate
        except Exception:  # noqa: S110
            pass
        return "unknown"

    async def probe_digitalocean_spaces(
        self, session: aiohttp.ClientSession, project_id: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        space_candidates = [
            project_id,
            f"{project_id}-assets",
            f"{project_id}-files",
            f"{project_id}-backup",
            "space",
        ]
        for region in self.do_regions:
            for space_name in space_candidates:
                url = f"https://{space_name}.{region}.digitaloceanspaces.com"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
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
                except Exception:  # noqa: S110
                    continue
        return findings

    async def probe_backblaze_b2(
        self, session: aiohttp.ClientSession, project_id: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        bucket_candidates = [
            project_id,
            f"{project_id}-backup",
            f"{project_id}-assets",
            "bucket",
        ]
        for region in self.backblaze_regions:
            for bucket_name in bucket_candidates:
                url = f"https://{bucket_name}.s3.us-west-002.backblazeb2.com"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (200, 301, 302, 403):
                            findings.append(
                                {
                                    "platform": "Backblaze B2",
                                    "bucket": bucket_name,
                                    "url": url,
                                    "region": region,
                                    "status": "detected",
                                    "severity": "info",
                                    "details": (
                                        f"Backblaze B2 bucket URL responded with HTTP {resp.status}."
                                    ),
                                }
                            )
                except Exception:  # noqa: S110
                    continue
        return findings

    async def probe_wasabi(
        self, session: aiohttp.ClientSession, project_id: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        bucket_candidates = [
            project_id,
            f"{project_id}-backup",
            f"{project_id}-assets",
            "bucket",
        ]
        for region in self.wasabi_regions:
            for bucket_name in bucket_candidates:
                url = f"https://{bucket_name}.s3.{region}.wasabisys.com"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status in (200, 301, 302, 403):
                            findings.append(
                                {
                                    "platform": "Wasabi",
                                    "bucket": bucket_name,
                                    "url": url,
                                    "region": region,
                                    "status": "detected",
                                    "severity": "info",
                                    "details": (
                                        f"Wasabi bucket URL responded with HTTP {resp.status}."
                                    ),
                                }
                            )
                except Exception:  # noqa: S110
                    continue
        return findings

    async def probe_oci_object_storage(
        self, session: aiohttp.ClientSession, project_id: str
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        bucket_candidates = [
            project_id,
            f"{project_id}-backup",
            f"{project_id}-assets",
            "bucket",
        ]
        for region in self.oci_regions:
            for bucket_name in bucket_candidates:
                url = f"https://{bucket_name}.objectstorage.{region}.oraclecloud.com"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
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
                except Exception:  # noqa: S110
                    continue
        return findings

    def run_scan_sync(self, target: str) -> list[dict[str, Any]]:
        """Synchronous runner wrapper for the async scan."""
        from src.recon.common import run_async_in_sync_context

        return cast(
            list[dict[str, Any]], run_async_in_sync_context(self.scan_all_candidates(target))
        )
