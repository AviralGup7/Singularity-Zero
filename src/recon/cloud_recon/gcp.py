from __future__ import annotations

import logging
from typing import Any

import aiohttp

from src.recon.cloud_recon.helpers import (
    _build_cloud_run_1st_gen_candidates,
    _build_cloud_run_2nd_gen_candidates,
)

logger = logging.getLogger(__name__)


class GCPCloudRecon:
    """GCP-specific cloud asset probes."""

    async def check_gcp_bucket(
        self,
        session: aiohttp.ClientSession,
        bucket: str,
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
                try:
                    async with session.get(
                        f"{url}?acl",
                        timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                    ) as acl_resp:
                        finding["permissions"]["read_acl"] = acl_resp.status == 200
                        if acl_resp.status == 200:
                            finding["severity"] = "high"
                            finding["details"] += " ACL is publicly readable."
                except Exception:  # noqa: S110
                    pass

                if getattr(self, "enable_write_probes", False):
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

    def enumerate_cloud_run_candidates(self, target: str) -> list[str]:
        from urllib.parse import urlparse

        from src.recon.cloud_recon.constants import (
            _GCP_CLOUD_RUN_REGION_TEMPLATES,
            _GCP_CLOUD_RUN_SERVICE_HINTS,
        )

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
        self,
        session: aiohttp.ClientSession,
        target: str,
    ) -> list[dict[str, Any]]:
        candidate_urls: set[str] = set()
        candidate_urls.update(_build_cloud_run_1st_gen_candidates(self, target))
        candidate_urls.update(_build_cloud_run_2nd_gen_candidates(self, target))
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

    def _build_cloud_run_1st_gen_candidates(self, target: str) -> list[str]:
        return _build_cloud_run_1st_gen_candidates(self, target)

    def _build_cloud_run_2nd_gen_candidates(self, target: str) -> list[str]:
        return _build_cloud_run_2nd_gen_candidates(self, target)

    async def probe_gcp_cloud_functions(
        self,
        session: aiohttp.ClientSession,
        project_id: str,
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
                except Exception:
                    logger.debug("GCP Cloud Function probe failed for %s", url)
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
        self,
        session: aiohttp.ClientSession,
        project_id: str,
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
            except Exception:
                logger.debug("GCP App Engine probe failed for %s", url)
                continue
        return findings
