from __future__ import annotations

import logging
from typing import Any

import aiohttp

from src.recon.cloud_recon.constants import (
    _DEFAULT_GCP_REGIONS,
    _GCP_CLOUD_RUN_REGION_TEMPLATES,
    _GCP_CLOUD_RUN_SERVICE_HINTS,
)

logger = logging.getLogger(__name__)


async def check_gcp_bucket(
    scanner: Any,
    session: aiohttp.ClientSession,
    bucket: str,
) -> dict[str, Any] | None:
    url = f"https://storage.googleapis.com/{bucket}"
    try:
        finding: dict[str, Any] | None = None
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds)
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
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
                ) as acl_resp:
                    finding["permissions"]["read_acl"] = acl_resp.status == 200
                    if acl_resp.status == 200:
                        finding["severity"] = "high"
                        finding["details"] += " ACL is publicly readable."
            except Exception:  # noqa: S110
                pass
            if getattr(scanner, "enable_write_probes", False):
                try:
                    async with session.put(
                        f"{url}/cyber_pipeline_write_test.txt",
                        data="test",
                        timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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


def enumerate_cloud_run_candidates(scanner: Any, target: str) -> list[str]:
    from urllib.parse import urlparse

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
    scanner: Any,
    session: aiohttp.ClientSession,
    target: str,
) -> list[dict[str, Any]]:

    candidate_urls: set[str] = set()
    candidate_urls.update(_build_cloud_run_1st_gen_candidates(scanner, target))
    candidate_urls.update(_build_cloud_run_2nd_gen_candidates(scanner, target))
    findings: list[dict[str, Any]] = []
    for candidate_url in candidate_urls:
        url = f"https://{candidate_url}"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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


async def probe_gcp_cloud_functions(
    scanner: Any,
    session: aiohttp.ClientSession,
    project_id: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for region in scanner.gcp_regions:
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
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
    second_gen_base = f"https://{project_id}-{scanner.gcp_regions[0]}.cloudfunctions.net"
    try:
        async with session.get(
            second_gen_base,
            timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
            allow_redirects=False,
        ) as resp:
            if resp.status in (200, 301, 302, 401, 403):
                findings.append(
                    {
                        "platform": "GCP Cloud Functions (2nd Gen)",
                        "url": second_gen_base,
                        "region": scanner.gcp_regions[0],
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
    scanner: Any,
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
                timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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


def _build_cloud_run_1st_gen_candidates(scanner: Any, target: str) -> list[str]:
    from urllib.parse import urlparse

    parsed = urlparse(target if "://" in target else f"https://{target}")
    domain = parsed.hostname or parsed.path or target
    core_name = domain.split(".")[0].lower().strip()
    if not core_name:
        return []
    candidates: set[str] = set()
    if getattr(scanner, "enable_cloud_run_enum", False):
        for hint in _GCP_CLOUD_RUN_SERVICE_HINTS:
            for region_tpl in _GCP_CLOUD_RUN_REGION_TEMPLATES:
                candidates.add(f"{core_name}-{hint}{region_tpl}")
                candidates.add(f"{core_name}{region_tpl}")
    return sorted(candidates)


def _build_cloud_run_2nd_gen_candidates(scanner: Any, target: str) -> list[str]:
    from urllib.parse import urlparse

    parsed = urlparse(target if "://" in target else f"https://{target}")
    domain = parsed.hostname or parsed.path or target
    core_name = domain.split(".")[0].lower().strip()
    if not core_name:
        return []
    candidates: set[str] = set()
    regions = getattr(scanner, "gcp_regions", None) or _DEFAULT_GCP_REGIONS
    if getattr(scanner, "enable_cloud_run_enum", False):
        for region in regions:
            candidates.add(f"{core_name}-{region}-uc.a.run.app")
            candidates.add(f"{core_name}-{region}.a.run.app")
            for h in _GCP_CLOUD_RUN_SERVICE_HINTS:
                candidates.add(f"{core_name}-{h}-{region}-uc.a.run.app")
                candidates.add(f"{core_name}-{h}-{region}.a.run.app")
    return sorted(candidates)


def _extract_region_from_url(scanner: Any, url: str) -> str:
    try:
        parts = url.split(".amazonaws.com")
        if parts:
            prefix = parts[0]
            region_candidate = prefix.split(".")[-2]
            if region_candidate not in {"s3", "execute-api", "vpce", "lambda-url"}:
                return region_candidate
    except Exception:
        pass
    return "unknown"


async def probe_aws_lambda_urls(
    scanner: Any, session: aiohttp.ClientSession, project_id: str
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
    for region in scanner.aws_regions:
        for func_name in function_candidates:
            url = f"https://{func_name}.lambda-url.{region}.on.aws"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
    scanner: Any, session: aiohttp.ClientSession, project_id: str
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
    for region in scanner.aws_regions:
        for api_id in api_candidates:
            urls = [
                f"https://{api_id}.execute-api.{region}.amazonaws.com",
                f"https://{api_id}.execute-api.{region}.vpce.amazonaws.com",
            ]
            for url in urls:
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
    scanner: Any, session: aiohttp.ClientSession, project_id: str
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
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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


async def probe_firebase_hosting(
    scanner: Any, session: aiohttp.ClientSession, project_id: str
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
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
            except Exception:
                logger.debug("Firebase Hosting probe failed for %s", url)
                continue
    return findings


async def probe_azure_functions(
    scanner: Any, session: aiohttp.ClientSession, project_id: str
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
    for region in scanner.azure_function_regions:
        for func in function_candidates:
            for azure_suffix in [
                f"{func}.{region}.azurewebsites.net",
                f"{func}.azurewebsites.net",
            ]:
                url = f"https://{azure_suffix}"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
                except Exception:
                    logger.debug("Azure Functions probe failed for %s", url)
                    continue
    return findings


async def probe_azure_logic_apps(
    scanner: Any, session: aiohttp.ClientSession, project_id: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    logic_candidates = [
        project_id,
        f"{project_id}-logic",
        f"{project_id}-workflow",
        "workflow",
        "logicapp",
    ]
    for region in scanner.azure_function_regions:
        for logic_name in logic_candidates:
            url = f"https://{logic_name}.{region}.logic.azure.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
            except Exception:
                logger.debug("Azure Logic Apps probe failed for %s", url)
                continue
    return findings


async def probe_azure_static_web_apps(
    scanner: Any, session: aiohttp.ClientSession, project_id: str
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
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
            except Exception:
                logger.debug("Azure Static Web Apps probe failed for %s", url)
                continue
    return findings


async def probe_s3_access_points(
    scanner: Any, session: aiohttp.ClientSession, base_name: str
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
        for region in scanner.aws_regions:
            url = f"https://{ap_name}-<account-id>.s3-accesspoint.{region}.amazonaws.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
            except Exception:
                logger.debug("S3 Access Point probe failed for %s", url)
                continue
    return findings


async def probe_multi_region_s3(
    scanner: Any, session: aiohttp.ClientSession, bucket: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    path_style_urls = [
        f"https://s3.{region}.amazonaws.com/{bucket}" for region in scanner.aws_regions
    ]
    vhost_style_urls = [
        f"https://{bucket}.s3.{region}.amazonaws.com" for region in scanner.aws_regions
    ]
    urls = path_style_urls + vhost_style_urls
    for url in urls:
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
                allow_redirects=False,
            ) as resp:
                if resp.status in (200, 301, 302, 403):
                    findings.append(
                        {
                            "platform": "AWS S3 Multi-Region",
                            "bucket": bucket,
                            "url": url,
                            "region": _extract_region_from_url(scanner, url),
                            "status": "detected",
                            "severity": "info",
                            "details": (f"S3 endpoint responded with HTTP {resp.status}."),
                        }
                    )
        except Exception:
            logger.debug("Multi-region S3 probe failed for %s", url)
            continue
    return findings


async def probe_digitalocean_spaces(
    scanner: Any, session: aiohttp.ClientSession, project_id: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    space_candidates = [
        project_id,
        f"{project_id}-assets",
        f"{project_id}-files",
        f"{project_id}-backup",
        "space",
    ]
    for region in scanner.do_regions:
        for space_name in space_candidates:
            url = f"https://{space_name}.{region}.digitaloceanspaces.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
            except Exception:
                logger.debug("DigitalOcean Spaces probe failed for %s", url)
                continue
    return findings


async def probe_backblaze_b2(
    scanner: Any, session: aiohttp.ClientSession, project_id: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    bucket_candidates = [
        project_id,
        f"{project_id}-backup",
        f"{project_id}-assets",
        "bucket",
    ]
    for region in scanner.backblaze_regions:
        for bucket_name in bucket_candidates:
            url = f"https://{bucket_name}.s3.us-west-002.backblazeb2.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
            except Exception:
                logger.debug("Backblaze B2 probe failed for %s", url)
                continue
    return findings


async def probe_wasabi(
    scanner: Any, session: aiohttp.ClientSession, project_id: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    bucket_candidates = [
        project_id,
        f"{project_id}-backup",
        f"{project_id}-assets",
        "bucket",
    ]
    for region in scanner.wasabi_regions:
        for bucket_name in bucket_candidates:
            url = f"https://{bucket_name}.s3.{region}.wasabisys.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
            except Exception:
                logger.debug("Wasabi probe failed for %s", url)
                continue
    return findings


async def probe_oci_object_storage(
    scanner: Any, session: aiohttp.ClientSession, project_id: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    bucket_candidates = [
        project_id,
        f"{project_id}-backup",
        f"{project_id}-assets",
        "bucket",
    ]
    for region in scanner.oci_regions:
        for bucket_name in bucket_candidates:
            url = f"https://{bucket_name}.objectstorage.{region}.oraclecloud.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=scanner.timeout_seconds),
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
            except Exception:
                logger.debug("OCI Object Storage probe failed for %s", url)
                continue
    return findings

