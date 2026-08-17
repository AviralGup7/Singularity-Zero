"""Azure Blob Storage, Functions, Logic Apps, and Static Web Apps checks."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)


async def check_azure_bucket(
    session: aiohttp.ClientSession,
    bucket: str,
    *,
    timeout_seconds: int = 5,
) -> dict[str, Any] | None:
    """Check Azure Blob Storage account status."""
    sanitized_bucket = "".join(c for c in bucket if c.isalnum()).lower()
    if not (3 <= len(sanitized_bucket) <= 24):
        return None

    url = f"https://{sanitized_bucket}.blob.core.windows.net"
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout_seconds)
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
            elif status == 200:
                return {
                    "platform": "Azure Blob Storage",
                    "bucket": sanitized_bucket,
                    "url": url,
                    "status": "public",
                    "severity": "high",
                    "details": "Storage container endpoint is accessible without authorization.",
                }
    except Exception:
        logger.warning("Operation failed in azure.py", exc_info=True)
    return None


async def probe_azure_functions(
    session: aiohttp.ClientSession,
    project_id: str,
    *,
    timeout_seconds: int = 5,
    azure_function_regions: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    from src.recon.cloud_recon.constants import _AZURE_FUNCTIONS_REGIONS

    findings: list[dict[str, Any]] = []
    regions = azure_function_regions or _AZURE_FUNCTIONS_REGIONS
    function_candidates = [
        project_id,
        f"{project_id}-function",
        f"{project_id}-api",
        "api",
        "function",
        "handler",
        "webhook",
    ]
    for region in regions:
        for func in function_candidates:
            for azure_suffix in [
                f"{func}.{region}.azurewebsites.net",
                f"{func}.azurewebsites.net",
            ]:
                url = f"https://{azure_suffix}"
                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=timeout_seconds),
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
    session: aiohttp.ClientSession,
    project_id: str,
    *,
    timeout_seconds: int = 5,
    azure_function_regions: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    from src.recon.cloud_recon.constants import _AZURE_FUNCTIONS_REGIONS

    findings: list[dict[str, Any]] = []
    regions = azure_function_regions or _AZURE_FUNCTIONS_REGIONS
    logic_candidates = [
        project_id,
        f"{project_id}-logic",
        f"{project_id}-workflow",
        "workflow",
        "logicapp",
    ]
    for region in regions:
        for logic_name in logic_candidates:
            url = f"https://{logic_name}.{region}.logic.azure.com"
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds),
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
                                "details": (f"Logic Apps URL responded with HTTP {resp.status}."),
                            }
                        )
            except Exception:
                logger.debug("Azure Logic Apps probe failed for %s", url)
                continue
    return findings


async def probe_azure_static_web_apps(
    session: aiohttp.ClientSession,
    project_id: str,
    *,
    timeout_seconds: int = 5,
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
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds),
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
